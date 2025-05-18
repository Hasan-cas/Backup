# Standard library imports
import os
import secrets
import logging
import requests
from logging.handlers import RotatingFileHandler
from decimal import Decimal
from datetime import datetime, timedelta , timezone
from uuid import uuid4
# Third-party imports
from io import BytesIO
from flask import Flask, render_template, request, url_for, session, jsonify, redirect , abort , send_file , send_from_directory
from flask_mail import Mail, Message
from urllib.parse import urlparse
from whitenoise import WhiteNoise
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress
from flask_session import Session
from dotenv import load_dotenv
import pymysql
pymysql.install_as_MySQLdb()
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.exc import IntegrityError
from itsdangerous import URLSafeTimedSerializer
#coustom imports made my me
from mail import mail, configure_mail ,get_email_provider # Import the mail module
from serializer import serializer , decrypt_csrf_token , encrypt_csrf_token

load_dotenv()

ph = PasswordHasher()

app = Flask(__name__,static_folder='static')

Compress(app)
limiter = Limiter(
    get_remote_address,  # Rate limit based on the user's IP
    default_limits=["100 per minute"]  # Default limit for all routes
)
limiter.init_app(app)
app.wsgi_app = WhiteNoise(app.wsgi_app, root='static/' , max_age=31536000)
# Secure configuration using environment variables
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config ['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript from accessing cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Stricter CSRF protection
app.config['SESSION_REFRESH_EACH_REQUEST'] = False  # Prevent session fixation attacks
if not app.config['SQLALCHEMY_DATABASE_URI'] or not app.config['SECRET_KEY']:
    raise ValueError("No DATABASE_URI or SECRET_KEY set for Flask application")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True}

REDEEM_CODES = os.getenv("REDEEM_CODES", "").split(",")
AUTHORIZED_IP = os.getenv("AUTHORIZED_IP")
csrf_code = os.getenv("CSRF_CODE")
money_map = {f"task_{i}": os.getenv(f"task_{i}") for i in range(1, 12)}

# Configure session to use SQLAlchemy
db = SQLAlchemy(app)

# Load backend URLs from environment variable
env_backend_api = os.getenv("BACKEND_API", "")
TARGET_URLS = [url.strip() for url in env_backend_api.split(",") if url.strip()]

# Extract allowed hostnames from TARGET_URLS
ALLOWED_HOSTS = [url.split("//")[-1] for url in TARGET_URLS]
ALLOWED_HOSTS += ["127.0.0.1", "localhost"]

# CSP setup
csp = {
    'default-src': ["'self'"],
    'img-src': ["'self'"] + TARGET_URLS,
    'style-src': ["'self'"] + TARGET_URLS,
    'script-src': ["'self'"] + TARGET_URLS,
    'connect-src': ["'self'"] + TARGET_URLS,
    'font-src': ["'self'"] + TARGET_URLS,
    'object-src': ["'none'"],
    'frame-src': ["'none'"],
    'base-uri': ["'self'"],
    'script-src-attr': ["'none'"],
    'form-action': ["'self'"],
    'upgrade-insecure-requests': []
}
csrf = Talisman(app,
                content_security_policy=csp,
                force_https=True,
                strict_transport_security=True,
                strict_transport_security_max_age=31536000,
                frame_options="DENY",  # Prevent clickjacking
                referrer_policy='no-referrer',  # Hide referrer info
                x_xss_protection=True,  # XSS Protection
                x_content_type_options="nosniff")  # Prevent MIME sniffing
# Configure the logger
logger = logging.getLogger('my_logger')
logger.setLevel(logging.DEBUG)

# Create a file handler that logs messages to a file with rotation
file_handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
file_handler.setLevel(logging.INFO)

# Create a console handler that logs to the console (stdout)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)  # Set this to the desired level for live logs

# Create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)  # This will ensure logs appear in Render’s live logs
# User model for storing credentials
class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True , index= True)
    password_hash = db.Column(db.String(256), nullable=False)  # To store hashed passwords
    token = db.Column(db.String(6), nullable=True)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    sessions = db.relationship('UserSession' , backref='user', lazy=True)

    def set_password(self, password):
        """Hashes the password using Argon2 and stores the hash."""
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        """Verifies the provided password against the stored hash."""
        try:
            return ph.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False
# Your models and routes would go here...
class UserSession(db.Model):
    __tablename__ = 'user_sessions'

    session_id = db.Column(db.String(256), nullable=False,unique=True)
    user_id = db.Column(db. Integer, db.ForeignKey('users.user_id'), nullable=False , primary_key=True)
    expiry = db.Column(db.DateTime, nullable=False)  # Expiry time of the session

    __table_args__ = {'extend_existing': True}
    def __init__(self, session_id, user_id, expiry):
        self.session_id = session_id
        self.user_id = user_id
        self.expiry = expiry

class Dashboard(db.Model):
    __tablename__ = 'dashboard'
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id') , primary_key=True)
    number = db.Column(db.Integer, nullable=False ,unique= False,default=0)
    coin = db.Column(db.Numeric(5,2), nullable=False,default=0)
    task_done = db.Column(db.Numeric(5,2), nullable=False,default=0)

class Button_id(db.Model):
    __tablename__ = 'button_id'

    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False , primary_key=True)  # User ID who redeemed the code
    button_name = db.Column(db.String(50), nullable=False)

class RedeemedCode(db.Model):
    __tablename__ = 'redeemedcode'

    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id') , nullable=False , primary_key=True)  # User ID who redeemed the code
    code = db.Column(db.String(50), nullable=False)  # Redeem code
    redeemed_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp for when it was redeemed

    # Ensure each code can only be used once per user
    __table_args__ = (db.UniqueConstraint('user_id', 'code', name='_user_code_uc'),)

class PaymentRequest(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id') , nullable=False , primary_key=True)  # User ID who request the code
    number = db.Column(db.Integer, nullable=False ,unique= False)
    amount = db.Column(db.String(50), nullable=False)  # Redeem code
    request_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp for when it was redeemed
@app.after_request
def add_corp_header(response):
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    return response
@app.before_request
def block_unwanted_hosts():
    request_host = request.host.split(":")[0]  # remove port
    if request_host not in ALLOWED_HOSTS:
        logging.warning(f"Blocked request from {request.host}")
        abort(403)
# Serve static files normally
@app.route('/static/<path:filename>')
def serve_static(filename):
    user_agent = request.user_agent.string.lower()

    # Check if it's an image (AVIF format) and has a "mobile-" version
    if filename.endswith('.avif'):
        is_mobile = any(keyword in user_agent for keyword in ["mobile", "android", "iphone", "ipad"])

        # If mobile, check if a "mobile-" version exists
        mobile_filename = f"mobile-{filename}"

        try:
            return send_from_directory("static", mobile_filename) if is_mobile else send_from_directory("static", filename)
        except:
            pass  # If mobile version is not found, serve the normal version

    # Serve all other static files normally
    return send_from_directory("static", filename)
@app.route("/ping")
def ping():
    return "OK", 200
@app.after_request
def add_cache_headers(response):
    """Automatically add cache headers for static files."""
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000'  # 1 year cache
    return response
def get_user_ip():
    forwarded = request.headers.get("X-Forwarded-For", request.remote_addr)
    return forwarded.split(",")[0].strip()  # Handles multiple forwarded IPs

def is_authorized_ip():
    return get_user_ip() == AUTHORIZED_IP

#Route for landing page
@app.route('/',methods=['POST', 'GET'])
def home():
    return render_template('index.html')

# Route for user registration (Signup)
@app.route('/signup', methods=['POST', 'GET'])
@limiter.limit("10 per minute")
def signup():
    try:
        if request.method == 'POST':
            if 'csrf_token' not in request.form or request.form['csrf_token'] != session.get('csrf_token'):
                return render_template('signup.html', text="Invaild request. Please try to colse tab and re-open the page.", status_2="-dismissible", status="-danger")
            existing_session = UserSession.query.filter_by(session_id=session.get('sid')).first()
            if existing_session :
                return render_template("dashboard.html", text ="You were already log in" ,status_2="-dismissible", status="-success")
            else :
                # Get form data
                username = request.form['username']
                email = request.form['email']
                password = request.form['password']
                if not username or not email or not password :
                    return redirect('/signup')
                # Check if the user already exists
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    return render_template('signup.html', text = "User already exists with this email address.",status_2="-dismissible", status="-success")
                else:
                    # Create a new user instance and hash the password
                    new_user = User(username=username, email=email , is_verified=False)
                    new_user.set_password(password)
                    try:
                        # Save the new user to the database
                        db.session.add(new_user)
                        db.session.commit()
                        # Redirect to login after successful signup
                        return redirect('/email-verification')

                    except IntegrityError as e:
                        db.session.rollback()  # Rollback transaction on error
                        return render_template('signup.html', text = "signup failed due to a database error",status_2="-dismissible", status="-danger")
        elif request.method == 'GET':
            csrf_token = str(uuid4())
            # Generate a random CSRF token
            session['csrf_token'] = csrf_token

            # Store CSRF token in session

            # Pass the CSRF token to the HTML template
            return render_template('signup.html',csrf_token=csrf_token )
    except Exception as e:
        # Get request details
        ip_address = request.remote_addr  # IP address of the requester
        user_agent = request.user_agent.string  # User agent of the requester
        user_id = session.get('user_id', 'Not logged in')  # Get user ID from session, if available

        # Log detailed error message
        logger.error(
            "An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}\n"
            )

        return render_template("error.html", message=f"An error occurred. Please try again.{e}")

# Route for email-Verification
@app.route('/email-verification', methods=['POST', 'GET'])
def email_verification():
    try:
        if request.method == 'POST':
            email = request.form['email']
            session['email'] = email
            provider = get_email_provider(email)
            if provider:
                configure_mail(app, provider)
                token = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
                user = User.query.filter_by(email=email).first()
                if user:
                    user.token = token
                    db.session.commit()
                    msg = Message(
                        subject="Email Verification",
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[email]
                    )
                    msg.body = f"Hello there. This is your verification code: {token}. Enter the code on your verification page."
                    with app.app_context():
                        mail.send(msg)
                    return render_template('verified.html', text="Verification email sent successfully.",status_2="-dismissible", status="-success")
                else:
                    return render_template('verification.html', text="No email is found. Please signup again.",status_2="-dismissible", status="-danger")
            else:  # This is line 222
                return render_template('verification.html', text="Unknown email provider.",status_2="-dismissible", status="-danger")
        elif request.method == 'GET':
            return render_template('verification.html')
    except Exception as e:
        # Get request details
        ip_address = request.remote_addr  # IP address of the requester
        user_agent = request.user_agent.string  # User agent of the requester
        user_id = session.get('user_id', 'Not logged in')  # Get user ID from session, if available
        # Log detailed error message
        logger.error(
            "An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}\n"
        )

        return render_template("error.html", message=f"An error occurred. Please try again. {e}")
# Route for code-Verification
@app.route('/verified', methods=['POST', 'GET'])
@limiter.limit("10 per minute")
def verified():
    try:
        if request.method == 'POST':
            token = request.form['code']
            email = session.get('email')
            visitor=User.query.filter_by(email=email).first()
            if visitor.is_verified == True :
                return redirect('/dashboard')
            if token == visitor.token :
                visitor.is_verified= True
                db.session.commit()
                return redirect('/dashboard')
            elif not token == visitor.token:
                return render_template('verification.html',text = "Code didnt match try again",status_2="-dismissible", status="-danger")
        elif request.method == 'GET':
            return render_template('verified.html')
    except Exception as e:
        # Get request details
        ip_address = request.remote_addr  # IP address of the requester
        user_agent = request.user_agent.string  # User agent of the requester
        user_id = session.get('user_id', 'Not logged in')  # Get user ID from session, if available

        # Log detailed error message
        logger.error(
            "An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}\n"
        )

        return render_template("error.html", message=f"An error occurred. Please try again. {e}")
# Route for user login
@app.route('/login', methods=['POST', 'GET'])
@limiter.limit("10 per minute")
def login():
    try:
        if request.method == 'POST':
            if 'csrf_token' not in request.form or request.form['csrf_token'] != session.get('csrf_token'):
                return render_template('signup.html', text="Invaild request. Please try to colse tab and re-open the page.",status_2="-dismissible", status="-danger")
            existing_session = UserSession.query.filter_by(session_id=session.get('sid')).first()
            if existing_session :
                return render_template("dashboard.html", text ="You were already log in",status_2="-dismissible", status="-success")
            else :
                email = request.form['email']
                password = request.form['password']
                if not email or not password :
                    csrf_token = session.get('csrf_token', str(uuid4()))
                    return render_template('register.html',text="Invaild request. Please try to colse tab and re-open the page.",status_2="-dismissible", status="-danger")
                user = User.query.filter_by(email=email).first()
                if user and user.is_verified != True:
                    return redirect("verification.html" , text = "You aren't verified. Please verify your identity",status_2="-dismissible", status="-danger")
                if user.check_password(password):
                    try:
                        session.permanent=True
                        # Generate session ID manually using uuid4
                        session_id = session.get('sid', str(uuid4()))
                        session['sid'] = session_id
                        session_user = session.get('user_id', user.user_id )
                        session['user_id'] = session_user
                        # Save session details in the UserSession model
                        new_user_session = UserSession(
                        session_id=session_id,  # Assuming session.sid is your session ID
                        user_id=user.user_id,# Creating a new user_id.

                        expiry = datetime.now(timezone.utc) + timedelta(days=30)
                        # Set expiry in 30 days
                        )
                        existing_user = UserSession.query.filter_by(user_id=user.user_id).first()
                        if not existing_user:
                            db.session.add(new_user_session)
                        if existing_user:
                            # If a session exists, update its session_id and expiry
                            existing_user.session_id = session_id
                            existing_user.expiry = datetime.now(timezone.utc) + timedelta(days=30)
                        db.session.commit()
                    except IntegrityError as e:
                        db.session.rollback()  # Rollback transaction on error
                        text = f"Signup failed due to a database error: {e}"
                        return render_template('register.html', text=text ,status_2="-dismissible")

                    return redirect('/dashboard')

                else:
                    return render_template('register.html', text = "Email or password is incorrect",status_2="-dismissible", status="-danger")

        elif request.method == 'GET':
            csrf_token = str(uuid4())
            # Generate a random CSRF token
            session['csrf_token'] = csrf_token

            return render_template('register.html', csrf_token = csrf_token)
    except Exception as e:
        # Get request details
        ip_address = request.remote_addr  # IP address of the requester
        user_agent = request.user_agent.string  # User agent of the requester
        user_id = session.get('user_id', 'Not logged in')  # Get user ID from session, if available

        # Log detailed error message
        logger.error(
            "An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}\n"
        )

        return render_template("register.html", message="An error occurred. Please try again.")
# Route for user dashboard
@app.route('/dashboard', methods=['POST', 'GET'])
def dashboard():
    try:
        if request.method == 'GET':
            existing_session = UserSession.query.filter_by(session_id=session.get('sid')).first()
            if not existing_session :
                return render_template("register.html" , text = "User isn't log in. Please log in first", status_2="-dismissible", status="-danger")
            user_id = session.get('user_id')
                # SQLAlchemy to filter tbe user
            user = User.query.filter_by(user_id=user_id).first()
            if user and user.is_verified == True:
                viewer = Dashboard.query.filter_by(user_id=user_id).first()
                #checking user exist or not

                if not viewer:
                    # If there's no existing viewer entry, create one
                    viewer = Dashboard(user_id=user_id, coin="0", task_done= "0")
                    #save as dashboard
                    db.session.add(viewer)
                    db.session.commit()

                    coin = viewer.coin
                    task_done = viewer.task_done
                    return render_template('dashboard.html', coin= coin, task_done=task_done )

                else:
                    #coin passing dashboard.coin as a coin amount
                    coin = viewer.coin
                    # task_done is passing dashboard.task_done as the amount of task has done
                    task_done = viewer.task_done
                    return render_template('dashboard.html', coin= coin, task_done=task_done )
            else :
                return redirect('/email-verification')

    except Exception as e:
        # Get request details
        ip_address = request.remote_addr  # IP address of the requester
        user_agent = request.user_agent.string  # User agent of the requester
        user_id = session.get('user_id', 'Not logged in')  # Get user ID from session, if available

        # Log detailed error message
        logger.error(
            "An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}\n"
        )

        return render_template("dashboard.html", message="An error occurred. Please try again.")
#route for /track-lead-post
@app.route('/track-lead-post', methods=['POST'])
def track_lead_post():
    try:
        if request.method == 'POST':
            if not request.is_json:
                return {"error": "Invalid request, JSON expected"}, 400
            data = request.get_json()
            ecrypt_token = data.get('csrf_token')
            session_data = data.get('sid')
            csrf_token = ecrypt_token #decrypt_csrf_token(ecrypt_token)
            csrf_entry = csrf_code #decrypt_csrf_token(csrf_code)
            user_id = data.get('user_id')
            button_name = data.get('button_name')
            if not str(csrf_token) or str(csrf_token) != str(csrf_entry):
                return render_template("dashboard.html", text="Task is not done",status_2="-dismissible", status="-danger")
            existing_session = UserSession.query.filter_by(session_id=session_data).first()

            if not existing_session:
                return render_template("register.html" , text = "User isn't log in. Please log in first",status_2="-dismissible", status="-danger")

            money = money_map.get(button_name)
            if money is None:
                return redirect('/dashboard')

            viewer = Dashboard.query.filter_by(user_id=user_id).first()
            button_query = Button_id(user_id=user_id, button_name=button_name)
            db.session.add(button_query)

            if not viewer:
                viewer = Dashboard(user_id=user_id, coin=0, task_done=0)
                db.session.add(viewer)
            viewer.coin = Decimal(viewer.coin or 0) + Decimal(money)
            viewer.task_done += 1
            db.session.commit()
            return redirect('/dashboard')
    except Exception as e:
        # Capture details of the error
        ip_address = request.remote_addr  # Get IP address
        user_agent = request.user_agent.string  # Get user agent
        user_id = session.get('user_id', 'Not logged in')  # Get user ID from session

        # Log detailed error message
        logger.error(
            f"An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}"
        )

        # Render error template
        return render_template("error.html", message=f"An error occurred. Please try again. {e}")
#route for /track-lead-get
@app.route('/track-lead-get', methods=['GET'])
def track_lead_get():
    try :
        if request.method == 'GET':
            ecrypt_token = request.args.get('csrf_token')
            button_name = request.args.get('button_name')
            if not ecrypt_token or not button_name:
                return redirect("/dashboard")
            data = {
                'csrf_token': ecrypt_token,
                'user_id': session.get('user_id'),
                'button_name': button_name,
                'sid': session.get('sid')

            }
            response = requests.post('https://skillcashify.onrender.com/track-lead-post', json=data)
            return render_template("cashify_academy_html/The-Journey.html")

    except Exception as e:
        # Capture details of the error
        ip_address = request.remote_addr  # Get IP address
        user_agent = request.user_agent.string  # Get user agent
        user_id = session.get('user_id', 'Not logged in')  # Get user ID from session

        # Log detailed error message
        logger.error(
            f"An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}"
        )

        # Render error template
        return render_template("error.html", message=f"An error occurred. Please try again. {e}")

@app.route('/blog-gallery', methods=['POST', 'GET'])
def blog_gallery():
    return render_template('cashify_academy_html/index.html')

@app.route('/the-journey', methods=['POST', 'GET'])
def the_journey():
    return render_template('cashify_academy_html/The-Journey.html')

@app.route('/drop-shipping', methods=['POST', 'GET'])
def drop_shipping():
    return render_template('cashify_academy_html/drop-shipping.html')

@app.route('/blog', methods=['POST', 'GET'])
def blog():
    return render_template('cashify_academy_html/blog.html')

@app.route('/about', methods=['POST', 'GET'])
def about():
    return render_template('cashify_academy_html/about.html')

@app.route('/redeem-code', methods=['POST', 'GET'])
def redeem_code():
    try:
        if request.method == 'POST':
            if 'csrf_token' not in request.form or request.form['csrf_token'] != session.get('csrf_token'):
                return render_template('redeem.html', text="Please reload the page",status_2="-dismissible", status="-danger")
            user_id = session.get('user_id')
            code = request.form.get('code')

            # Validate if user is logged in
            if not user_id:
                return render_template("register.html" , text = "User isn't log in. Please log in first",status_2="-dismissible", status="-danger")

            # Check if the entered code is in the valid codes from .env
            if code not in REDEEM_CODES:
                return render_template('redeem.html', text="Invalid redeem code.",status_2="-dismissible", status="-danger")

            # Check if the user has already redeemed this code
            already_redeemed = RedeemedCode.query.filter_by(user_id=user_id, code=code).first()
            if already_redeemed:
                return render_template('redeem.html', text="You already redeemed the code.",status_2="-dismissible", status="-danger")

            # If code is valid and not yet redeemed, save it in the database
            new_redeem = RedeemedCode(user_id=user_id, code=code)
            db.session.add(new_redeem)
            db.session.commit()

            # Optionally, grant the user a reward
            viewer = Dashboard.query.filter_by(user_id=user_id).first()
            if viewer:
                viewer.coin = Decimal(viewer.coin) + Decimal('0.03')      # Example reward
                db.session.commit()
                return render_template('redeem.html',text=f"Code verified you have now ${viewer.coin}",status_2="-dismissible", status="-success")
        # For GET requests, render the redeem page with a form to enter code
        elif request.method == 'GET':
            csrf_token = str(uuid4())
            # Generate a random CSRF token
            session['csrf_token'] = csrf_token

            return render_template('redeem.html', csrf_token = csrf_token )

    except Exception as e:
        # Capture details of the error
        ip_address = request.remote_addr  # Get IP address
        user_agent = request.user_agent.string  # Get user agent
        user_id = session.get('user_id', 'Not logged in')  # Get user ID from session

        # Log detailed error message
        logger.error(
            f"An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}"
        )

        # Render error template
        return render_template("error.html", message=f"An error occurred. Please try again. {e}")


@app.route('/get-done', methods=['GET'])
def get_done():
    try:
        user_id = session.get('user_id')
        button_names = Button_id.query.filter_by(user_id=user_id).all()
        task_name = [task.button_name for task in button_names]
        logger.error(task_name)
        return jsonify(task_name)
    except Exception as e:
        # Capture details of the error
        ip_address = request.remote_addr  # Get IP address
        user_agent = request.user_agent.string  # Get user agent
        user_id = session.get('user_id', 'Not logged in')  # Get user ID from session

        # Log detailed error message
        logger.error(
            f"An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}"
        )

        # Render error template
        return render_template("error.html", message=f"An error occurred. Please try again. {e}")

@app.route('/request-paymemt', methods=['POST', 'GET'])
def request_payment():
    try:
        if request.method == 'POST':
            # CSRF token validation to prevent cross-site request forgery attacks
            if 'csrf_token' not in request.form or request.form['csrf_token'] != session.get('csrf_token'):
                return render_template('request.html', text="Invalid request", status="-danger", status_2="-dismissible")  # Respond with an error message if CSRF token is invalid

            # Fetch the existing session based on the session ID stored in the session
            existing_session = UserSession.query.filter_by(session_id=session.get('sid')).first()
            if existing_session:
                # If the session is valid, retrieve user data from the session
                user_id = session.get('user_id')
                viewer = Dashboard.query.filter_by(user_id=user_id).first()

                # Ensure the user exists in the dashboard
                if not viewer:
                    return render_template("dashboard.html", text="Try again now . Error fixed", status="-danger",status_2="-dismissible")  # Show an error if user data isn't found
                coin = viewer.coin
                if coin <= 10000:
                    return render_template('request.html',text ="Not enough coin", status="-danger",status_2="-dismissible")
                # Calculate the payment amount (based on user's coins)
                amount = coin  / 10  # Amount is 1/10th of the user's coin value
                username = request.form['username']
                number = request.form['number']
                payment_provider = request.form['paymentMethod']
                feedback = request.form['feedback']

                # Ensure all required form fields are provided
                if not user_id or not amount or not username or not number or not payment_provider:
                    return render_template('request.html', text="Some information is missing like user_id, username, number, payment_provider etc", status="-danger",status_2="-dismissible")

                # Save the payment request to the database
                save_request = PaymentRequest(
                    user_id=user_id,  # Creating a new user_id.
                    amount=amount,  # Amount of money
                    username=username,  # Person's name
                    number=number,  # Phone number for payment
                    payment_provider=payment_provider,  # Payment provider (bKash, Nogat)
                    feedback=feedback,  # User feedback
                    request_at=datetime.now(timezone.utc)  # Record the request time in UTC
                )

                # Add the payment request to the session and commit to the database
                db.session.add(save_request)
                db.session.commit()
                return render_template("request.html", text="Thanks for your job. The Payment Request is sent. You will receive payment soon.", status="-success",status_2="-dismissible")

        elif request.method == 'GET':
            # Generate a new CSRF token for GET requests to prevent cross-site scripting
            csrf_token = str(uuid4())
            session['csrf_token'] = csrf_token

            return render_template('request.html', csrf_token=csrf_token)  # Send the CSRF token with the form

    except Exception as e:
        # Capture error details for logging and troubleshooting
        ip_address = request.remote_addr  # Get user's IP address
        user_agent = request.user_agent.string  # Get the user's browser and device details
        user_id = session.get('user_id', 'Not logged in')  # Get user ID or 'Not logged in' if the user is not authenticated

        # Log the error details with all relevant information
        logger.error(
            f"An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}"
        )

        # Render an error page if any exception occurs
        return render_template("error.html", message=f"An error occurred. Please try again. {e}")

@app.route('/get_taka', methods=['POST', 'GET'])
def get_taka():
    try:
        logger.error("Entered /get_taka route")
        if not is_authorized_ip():
            return "Access Denied: This endpoint is restricted.", 400
        if request.method == 'POST':
            logger.error("POST request detected")

            if 'csrf_token' not in request.form or request.form['csrf_token'] != session.get('csrf_token'):
                logger.error("CSRF token validation failed")
                return redirect("/")

            USERNAME = os.getenv('USERNAME')
            PASSWORD = os.getenv('PASSWORD')
            logger.error(f"The env variables are {PASSWORD} and {USERNAME}")
            root_pass = decrypt_csrf_token(PASSWORD)
            logger.error(f"Loaded USERNAME: {USERNAME}, Decrypted PASSWORD: {root_pass}")

            username = request.form['username']
            password = request.form['password']

            if not username or not password:
                logger.error("Username or Password is missing")
                return redirect("/")

            if username == USERNAME and password == root_pass:
                logger.error("User authenticated successfully")
                db_path = os.path.join(app.instance_path, "cashify.db")
                logger.error(f"Database path: {db_path}")

                if os.path.exists(db_path):
                    logger.error("Database found, preparing file download")
                    return send_file(db_path, as_attachment=True)
                else:
                    logger.error("Database file not found")
                    return abort(404, description="Database not found")

        elif request.method == 'GET':
            logger.error("GET request detected")

            csrf_token = str(uuid4())
            session['csrf_token'] = csrf_token
            logger.error(f"Generated CSRF Token: {csrf_token}")

            return render_template('print.html', csrf_token=csrf_token)
    except Exception as e:
        # Capture error details for logging and troubleshooting
        ip_address = request.remote_addr  # Get user's IP address
        user_agent = request.user_agent.string  # Get the user's browser and device details
        user_id = session.get('user_id', 'Not logged in')  # Get user ID or 'Not logged in' if the user is not authenticated

        # Log the error details with all relevant information
        logger.error(
            f"An error occurred:\n"
            f"  - Endpoint: {request.path}\n"
            f"  - Method: {request.method}\n"
            f"  - User ID: {user_id}\n"
            f"  - IP Address: {ip_address}\n"
            f"  - User Agent: {user_agent}\n"
            f"  - Error Message: {str(e)}"
        )

        # Render an error page if any exception occurs
        return render_template("error.html", message=f"An error occurred. Please try again. {e}")
gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(logging.DEBUG)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)