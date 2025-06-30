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






app = Flask(__name__)
app.secret_key = "super_secret_key"

# ----------------------------- Database Setup -----------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://admin:VUdnYr3IkmR5B8nIemLx41l5LgwimFIJ@dpg-d1h8292li9vc73bf71dg-a/muzzboost"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ----------------------------- Models -----------------------------
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stock_name = db.Column(db.String(100), nullable=False)
    stock_amount = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    undone = db.Column(db.Boolean, default=False)




class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(50), default='user')  # 'admin' or 'user'
    confirmed = db.Column(db.Boolean, default=False)


ADMIN_EMAILS = {"ethanplm091@gmail.com", "ethanplm1@gmail.com", "danielelrond98@gmail.com", "rowan.kelly@mn.catholic.edu.au"}


with app.app_context():
    db.drop_all()
    db.create_all()

with app.app_context():
    admin_user = User.query.filter_by(email="ethanplm091@gmail.com").first()
    if admin_user:
        admin_user.role = 'admin'
        db.session.commit()



login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Mail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'muzzboost@gmail.com'  # Change this
app.config['MAIL_PASSWORD'] = 'ujpt ggtd uscw fmzt'     # Use App Password, not your Gmail password

mail = Mail(app)

# ----------------------------- Login Restriction Setup -----------------------------
# Only allow these specific emails to log in
AUTHORIZED_EMAILS = {"ethanplm091@gmail.com"}  # ✅ Add more like: {"ethanplm091@gmail.com", "another@email.com"}

# ----------------------------- Routes -----------------------------
@app.route("/")
def home():
    # Pass session to the template so you can use {% if session['user_id'] %} in main.html
    return render_template("main.html", session=session)

# ----------------------------- Signup Route -----------------------------
s = URLSafeTimedSerializer(app.secret_key)

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
    confirm_url = url_for('confirm_email', token=token, _external=True)

    # ✅ Determine role based on email
    if email == {"ethanplm091@gmail.com","rowan.kelly@mn.catholic.edu.au"}:
        role = "admin"
    elif email in {"ethanplm1@gmail.com", "danielelrond98@gmail.com"}:
        role = "viewer"
    else:
        return "Unauthorized: You are not allowed to register."

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

    return render_template("confirmation_sent.html", email=email)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403)
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

    return render_template("email_confirmed.html")





# ----------------------------- Login Route -----------------------------

@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    password = request.form["password"]

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return "Invalid credentials"

    if not user.confirmed:
        return "Please confirm your email before logging in."

    # ✅ Allow only users with a known role
    if user.role not in {"admin", "viewer"}:
        return render_template_string("""
            <h2 style="font-family:sans-serif; color:red;">Access Denied</h2>
            <p>Your email is not currently authorized to access this platform.</p>
            <p>Please contact <a href="mailto:muzzboost@gmail.com">muzzboost@gmail.com</a> to request access.</p>
            <a href="/">Return to Home</a>
        """)

    login_user(user)
    return redirect(url_for("order_form"))


# ----------------------------- Logout Route -----------------------------
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("home"))

# ----------------------------- Order Form Page -----------------------------
@app.route("/order", methods=["GET"])
@login_required
@admin_required
def order_form():
    return render_template("database.html")

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
        return redirect(url_for("stock_summary"))



# ----------------------------- Stock Summary Page -----------------------------
@app.route('/stock-summary')
@login_required
def stock_summary():
    if current_user.role not in {"admin", "viewer"}:
        abort(403)

    summary = db.session.query(
        Order.stock_name,
        db.func.sum(Order.stock_amount).label("total")
    ).filter_by(undone=False).group_by(Order.stock_name).all()

    order_history = []
    if current_user.role == "admin":
        order_history = Order.query.order_by(Order.timestamp.desc()).all()

    return render_template("stock_summary.html", summary=summary, order_history=order_history)



@app.route("/undo-order/<int:order_id>", methods=["POST"])
@login_required
def undo_order(order_id):
    order = Order.query.get_or_404(order_id)
    order.undone = True
    db.session.commit()
    return redirect("/stock-summary")





# ----------------------------- Run the App -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # ✅ Needed for Render deployment
    app.run(host="0.0.0.0", port=port, debug=True)
