from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os # For setting the secret key securely

app = Flask(__name__)

# --- Configuration ---
# Generate a strong secret key for production:
# You can generate one with `os.urandom(24).hex()` and store it in an environment variable.
# For development, you can use a placeholder, but NEVER in production.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_very_secret_key_that_should_be_long_and_random')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login if not authenticated
login_manager.login_message_category = 'info' # Category for the default login required message

# --- Database Model ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user') # For authorization example

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    """Callback function to reload the user object from the user ID stored in the session."""
    return User.query.get(int(user_id))

# --- Authorization Decorator ---
def admin_required(f):
    """Custom decorator to restrict access to admin users only."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login', next=request.url))
        if current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard')) # Redirect non-admins to dashboard
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def home():
    """Home page."""
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Basic input validation
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html', username=username, email=email) # Pass back entered values

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html', username=username, email=email)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', email=email)

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already registered. Please use a different one.', 'danger')
            return render_template('register.html', username=username)

        try:
            new_user = User(username=username, email=email)
            new_user.set_password(password) # Securely hash password
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback() # Rollback in case of error
            flash(f'An error occurred during registration: {str(e)}', 'danger')
            app.logger.error(f"Registration error: {e}") # Log the error
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=remember) # Remember me functionality
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next') # Redirect to the page user was trying to access
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required # Requires user to be logged in to access this route
def logout():
    """User logout route."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required # This route requires authentication
def dashboard():
    """User dashboard page."""
    return render_template('dashboard.html', user=current_user)

@app.route('/admin')
@login_required # Must be logged in
@admin_required # Must have 'admin' role
def admin_panel():
    """Admin panel page."""
    users = User.query.all() # Fetch all users for display
    return render_template('admin_panel.html', users=users)

# --- Database Initialization on App Start ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create database tables if they don't exist
        # Optional: Create an initial admin user if no users exist
        if User.query.count() == 0:
            print("No users found. Creating a default admin user...")
            admin_user = User(username='admin', email='admin@example.com', role='admin')
            admin_user.set_password('adminpassword') # **CHANGE THIS PASSWORD IMMEDIATELY**
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user 'admin' created with password 'adminpassword'.")
            print("Please change this password after first login for security!")
    app.run(debug=True) # debug=True is for development only! Set to False in production.
