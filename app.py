from flask import Flask, render_template, request, redirect, url_for, session, render_template_string
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from functools import wraps
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer



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
    stock_amount = db.Column(db.String(50), nullable=False)
    real_name = db.Column(db.String(100), nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)  # ✅ Add this


with app.app_context():
    db.drop_all()
    db.create_all()


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

# ----------------------------- Login Required Decorator -----------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function

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

    msg = Message('Confirm your MuzzBoost account',
                  sender='muzzboost@gmail.com',
                  recipients=[email])
    msg.body = f'Click the link to confirm: {confirm_url}'
    mail.send(msg)

    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return "Please check your email to confirm your account."


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

    if email not in AUTHORIZED_EMAILS:
        return "Unauthorized: You do not have access"

    session["user_id"] = user.id
    return redirect(url_for("order_form"))


# ----------------------------- Logout Route -----------------------------
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("home"))

# ----------------------------- Order Form Page -----------------------------
@app.route("/order", methods=["GET"])
@login_required
def order_form():
    return render_template("database.html")

# ----------------------------- Order Submission -----------------------------
@app.route("/order-completion", methods=["GET", "POST"])
@login_required
def order_completion():
    if request.method == "POST":
        stock_names = request.form.getlist("stockName")
        stock_amounts = request.form.getlist("stockAmount")
        stock_actions = request.form.getlist("stockAction")
        real_name = request.form.get("realName")

        if not stock_names or not stock_amounts or not stock_actions or not real_name:
            return "Missing data", 400

        for name, amount, action in zip(stock_names, stock_amounts, stock_actions):
            signed_amount = f"-{amount}" if action == "remove" else amount
            new_order = Order(stock_name=name, stock_amount=signed_amount, real_name=real_name)
            db.session.add(new_order)

        db.session.commit()
        return f"<h2>Thanks {real_name}, your stock update has been received!</h2><a href='/'>Back to Home</a>"

    return redirect(url_for("order_form"))

# ----------------------------- Stock Summary Page -----------------------------
@app.route("/stock-summary", methods=["GET", "POST"])
@login_required
def stock_summary():
    user = User.query.get(session["user_id"])
    group_by_name = request.form.get("groupByName") == "on"


    if group_by_name:
        summary = db.session.query(
            Order.stock_name,
            Order.real_name,
            func.sum(Order.stock_amount).label("total")
        ).group_by(Order.stock_name, Order.real_name).all()
    else:
        summary = db.session.query(
            Order.stock_name,
            func.sum(Order.stock_amount).label("total")
        ).group_by(Order.stock_name).all()

    return render_template_string("""
        <h2>Stock Summary</h2>
        <p>Logged in as: {{ user.email }}</p>
        <form method="POST">
            <label><input type="checkbox" name="groupByName" {% if group_by_name %}checked{% endif %}> Group by Name</label>
            <button type="submit">Update</button>
        </form>
        <table border="1">
            <tr>
                <th>Stock</th>
                {% if group_by_name %}<th>Name</th>{% endif %}
                <th>Total Quantity</th>
            </tr>
            {% for row in summary %}
            <tr>
                <td>{{ row[0] }}</td>
                {% if group_by_name %}<td>{{ row[1] }}</td>{% endif %}
                <td>{{ row[-1] }}</td>
            </tr>
            {% endfor %}
        </table>
    """, summary=summary, group_by_name=group_by_name)

# ----------------------------- Run the App -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # ✅ Needed for Render deployment
    app.run(host="0.0.0.0", port=port, debug=True)
