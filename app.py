from flask import Flask, render_template, request, redirect, url_for, session, render_template_string, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, cast, Integer
from functools import wraps
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from flask_login import current_user, UserMixin, LoginManager, login_user, login_required, logout_user
import pytz







app = Flask(__name__)  # Create Flask app instance
app.secret_key = "super_secret_key"  # Secret key for session management and token signing

# ----------------------------- Database Setup -----------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://admin:VUdnYr3IkmR5B8nIemLx41l5LgwimFIJ@dpg-d1h8292li9vc73bf71dg-a/muzzboost"  # Database connection string for PostgreSQL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # Disable tracking modifications to save resources
db = SQLAlchemy(app)

# ----------------------------- Models -----------------------------
class Order(db.Model):  # Model to represent stock orders
    id = db.Column(db.Integer, primary_key=True)
    stock_name = db.Column(db.String(100), nullable=False)
    stock_amount = db.Column(db.Integer, nullable=False)
    real_name = db.Column(db.String(100), nullable=True)  
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    undone = db.Column(db.Boolean, default=False)


class AlertEmail(db.Model):  # Model to store emails for low stock alerts
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=True)

class LowStockFlag(db.Model):  # Flags to prevent duplicate low stock emails
    id = db.Column(db.Integer, primary_key=True)
    stock_name = db.Column(db.String(100), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=True)



class User(db.Model, UserMixin):  # User model for login and role management
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(50), default='user')  # 'admin' or 'user'
    confirmed = db.Column(db.Boolean, default=False)


ADMIN_EMAILS = {"ethanplm091@gmail.com", "rowan.kelly@mn.catholic.edu.au"}  # Set of admin-authorized email addresses
VIEWER_EMAILS = {"ethanplm1@gmail.com", "danielelrond98@gmail.com"}  # Set of viewer-only email addresses

LOW_STOCK_THRESHOLD = 5  # Threshold below which stock is considered low


with app.app_context():
    db.drop_all()  # Drop all existing tables in the database
    db.create_all()  # Recreate all tables based on models


with app.app_context():
    users = User.query.all()
    for user in users:
        if user.email in ADMIN_EMAILS:  # Set of admin-authorized email addresses
            user.role = 'admin'
        elif user.email in VIEWER_EMAILS:  # Set of viewer-only email addresses
            user.role = 'viewer'
        else:
            user.role = 'unauthorized'
    db.session.commit()



login_manager = LoginManager()  # Set up login manager for Flask-Login
login_manager.init_app(app)

@login_manager.user_loader  # Decorator to tell Flask-Login how to load a user
def load_user(user_id):  # Function to load user by ID
    return User.query.get(int(user_id))


# Mail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Configuration for email SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'muzzboost@gmail.com'  
app.config['MAIL_PASSWORD'] = 'ujpt ggtd uscw fmzt'   

mail = Mail(app)  # Initialize Flask-Mail

# ----------------------------- Login Restriction Setup -----------------------------
# Only allow these specific emails to log in
AUTHORIZED_EMAILS = {"ethanplm091@gmail.com"}  

# ----------------------------- Routes -----------------------------
@app.route("/")
def home():
    # Pass session to the template so you can use {% if session['user_id'] %} in main.html
    return render_template("main.html", session=session)  # Render an HTML template and return response

# ----------------------------- Signup Route -----------------------------


def notify_admins_low_stock(stock_name, total_amount):
    # Always include Ethan
    default_recipient = "ethanplm091@gmail.com"
    extra_recipients = [e.email for e in AlertEmail.query.all()]
    recipients = list(set([default_recipient] + extra_recipients))

    subject = f"🔔 Low Stock Alert: {stock_name}"
    body = f"The stock level for '{stock_name}' has dropped to {total_amount} units. Please take necessary action."

    msg = Message(subject, sender='muzzboost@gmail.com', recipients=recipients)
    msg.body = body
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending low stock email: {e}")





s = URLSafeTimedSerializer(app.secret_key)  # Secret key for session management and token signing

@app.route("/signup", methods=["POST"])
def signup():
    email = request.form["email"]
    password = request.form["psw"]
    repeat_password = request.form["psw-repeat"]

    if password != repeat_password:
        return "Passwords do not match"

    if User.query.filter_by(email=email).first():
        return "User already exists"

    token = s.dumps(email, salt='email-confirm')
    confirm_url = url_for('confirm_email', token=token, _external=True)  # Generate a URL for a given endpoint

    # ✅ Determine role based on email
    if email in ADMIN_EMAILS:  # Set of admin-authorized email addresses
        role = "admin"
    elif email in VIEWER_EMAILS:  # Set of viewer-only email addresses
        role = "viewer"
    else:
        return render_template_string("""  # Render an HTML template and return response
            <h2 style="font-family:sans-serif; color:red;">Unauthorized</h2>
            <p>You are not allowed to register with this email.</p>
            <p>Please contact <a href="mailto:muzzboost@gmail.com">muzzboost@gmail.com</a> to request access.</p>
            <a href="/">Return to Home</a>
        """)


    hashed_password = generate_password_hash(password)

    # ✅ Correct creation with role
    new_user = User(email=email, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    # ✅ Send confirmation email
    msg = Message('Confirm your MuzzBoost account',
                  sender='muzzboost@gmail.com',
                  recipients=[email])
    msg.html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 30px;">
        <div style="max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
          <h2 style="color: #0074D9;">Welcome to MuzzBoost</h2>
          <p>Hi there,</p>
          <p>Thank you for signing up! To complete your registration, please verify your email address by clicking the button below:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{confirm_url}" style="background-color: #0074D9; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">
              Confirm My Email
            </a>
          </div>
          <p>If you did not request this, you can safely ignore this email.</p>
          <hr style="margin-top: 40px;">
          <p style="font-size: 12px; color: #888;">MuzzBoost Team<br>Do not reply to this automated email.</p>
        </div>
      </body>
    </html>
    """
    mail.send(msg)

    return render_template("confirmation_sent.html", email=email)  # Render an HTML template and return response


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403)  # Stop request with a Forbidden error if unauthorized
        return f(*args, **kwargs)
    return decorated_function

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        return "The confirmation link is invalid or has expired."

    user = User.query.filter_by(email=email).first()
    if not user:
        return "User not found"

    user.confirmed = True
    db.session.commit()

    return render_template("email_confirmed.html")  # Render an HTML template and return response





# ----------------------------- Login Route -----------------------------

@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    password = request.form["password"]
    user = User.query.filter_by(email=email).first()

    if user:
        if not user.confirmed:
            flash("Your account is not verified. Please contact muzzboost091@gmail.com to be added.", "danger")  # Display a flash message to user
            return redirect("/")  # Redirect to another route
        if check_password_hash(user.password, password):
            login_user(user)
            session["user_id"] = user.id
            return redirect("/order" if user.role == "admin" else "/stock-summary")  # Redirect to another route
        else:
            flash("Incorrect password. Please try again.", "danger")  # Display a flash message to user
            return redirect("/")  # Redirect to another route
    else:
        flash("Email not found. Please sign up or contact support.", "danger")  # Display a flash message to user
        return redirect("/")  # Redirect to another route



# ----------------------------- Logout Route -----------------------------
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("home"))  # Redirect to another route

# ----------------------------- Order Form Page -----------------------------
@app.route("/order", methods=["GET"])
@login_required
@admin_required
def order_form():
    return render_template("database.html")  # Render an HTML template and return response

# ----------------------------- Order Submission -----------------------------
@app.route("/order-completion", methods=["GET", "POST"])
@login_required
@admin_required
def order_completion():
    if request.method == "POST":
        stock_names = request.form.getlist("stockName")
        stock_amounts = request.form.getlist("stockAmount")
        stock_actions = request.form.getlist("stockAction")
        real_name = request.form.get("realName")

        if not stock_names or not stock_amounts or not stock_actions or not real_name:
            return "Missing data", 400

        for name, amount, action in zip(stock_names, stock_amounts, stock_actions):
            signed_amount = -int(amount) if action == "remove" else int(amount)
            new_order = Order(stock_name=name, stock_amount=signed_amount, real_name=real_name)
            db.session.add(new_order)

        db.session.commit()

        low_stock_items = db.session.query(
    Order.stock_name,
    db.func.sum(Order.stock_amount).label("total")
).filter_by(undone=False).group_by(Order.stock_name).having(
    db.func.sum(Order.stock_amount) < LOW_STOCK_THRESHOLD  # Threshold below which stock is considered low
).all()

        db.session.commit()

        low_stock_items = db.session.query(
            Order.stock_name,
            db.func.sum(Order.stock_amount).label("total")
        ).filter_by(undone=False).group_by(Order.stock_name).having(
            db.func.sum(Order.stock_amount) < LOW_STOCK_THRESHOLD  # Threshold below which stock is considered low
        ).all()

        for item in low_stock_items:
            flag = LowStockFlag.query.filter_by(stock_name=item.stock_name).first()
            if not flag:
                notify_admins_low_stock(item.stock_name, item.total)
                db.session.add(LowStockFlag(stock_name=item.stock_name, active=True))
            elif not flag.active:
                notify_admins_low_stock(item.stock_name, item.total)
                flag.active = True

        # ✅ Clear flags if restocked
        recovered_stock_items = db.session.query(
            Order.stock_name,
            db.func.sum(Order.stock_amount).label("total")
        ).filter_by(undone=False).group_by(Order.stock_name).having(
            db.func.sum(Order.stock_amount) >= LOW_STOCK_THRESHOLD  # Threshold below which stock is considered low
        ).all()

        for item in recovered_stock_items:
            flag = LowStockFlag.query.filter_by(stock_name=item.stock_name).first()
            if flag and flag.active:
                flag.active = False

        db.session.commit()
        return redirect(url_for("stock_summary"))  # Redirect to another route



# ----------------------------- Stock Summary Page -----------------------------
@app.route('/stock-summary')
@login_required
def stock_summary():
    if current_user.role not in {"admin", "viewer"}:
        abort(403)  # Stop request with a Forbidden error if unauthorized

    summary = db.session.query(
        Order.stock_name,
        db.func.sum(Order.stock_amount).label("total")
    ).filter_by(undone=False).group_by(Order.stock_name).all()

    order_history = []
    if current_user.role == "admin":
        aest = pytz.timezone("Australia/Sydney")
        order_history = [
            {
                "id": order.id,
                "stock_name": order.stock_name,
                "stock_amount": order.stock_amount,
                "real_name": order.real_name,
                "timestamp": order.timestamp.astimezone(aest),
                "undone": order.undone
            }
            for order in Order.query.order_by(Order.timestamp.desc()).all()
        ]      


    return render_template("stock_summary.html", summary=summary, order_history=order_history)  # Render an HTML template and return response

@app.route("/add-alert-email", methods=["POST"])
@login_required
@admin_required
def add_alert_email():
    email = request.form.get("email")
    if not email:
        return "Missing email", 400

    if not AlertEmail.query.filter_by(email=email).first():
        new_email = AlertEmail(email=email)
        db.session.add(new_email)
        db.session.commit()

    return redirect("/order")  # Redirect to another route


@app.route("/undo-order/<int:order_id>", methods=["POST"])
@login_required
def undo_order(order_id):
    order = Order.query.get_or_404(order_id)
    order.undone = True
    db.session.commit()
    return redirect("/stock-summary")  # Redirect to another route

@app.route("/add-role", methods=["POST"])
@login_required
@admin_required
def add_role():
    email = request.form.get("email")
    role = request.form.get("role")

    if not email or role not in {"admin", "viewer"}:
        return "Invalid submission", 400

    # Add email to the correct set
    if role == "admin":
        ADMIN_EMAILS.add(email)  # Set of admin-authorized email addresses
    elif role == "viewer":
        VIEWER_EMAILS.add(email)  # Set of viewer-only email addresses

    # Update role in DB if user exists
    user = User.query.filter_by(email=email).first()
    if user:
        user.role = role
        db.session.commit()

    return redirect("/stock-summary")  # Redirect to another route


# ----------------------------- Run the App -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # ✅ Needed for Render deployment
    app.run(host="0.0.0.0", port=port, debug=True)  # Run the Flask development server
