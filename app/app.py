import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo

# Ensure the upload folder exists
if not os.path.exists('static/profile_pics'):
    os.makedirs('static/profile_pics')

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')  # Better to use an env variable
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # SQLite URI for permanent storage
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Database and LoginManager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model definition
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user')  # Default role is 'user'
    profile_pic = db.Column(db.String(120), default='default.jpg')  # Profile pic column

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper function for allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    # Username field with minimum and maximum length validation
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=4, max=20, message="Username must be between 4 and 20 characters")
    ])
    
    # Email field with email format validation
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email address")
    ])
    
    # Password field with minimum length validation
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=6, message="Password must be at least 6 characters long")
    ])
    
    # Confirm password field with matching password validation
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ])
    
    # Role selection with options for 'user' and 'admin'
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[
        DataRequired(message="Please select a role")
    ])
    
    # Submit button for registration
    submit = SubmitField('Register')
    
class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[Length(min=3, max=20)])
    email = StringField('Email', validators=[Email()])

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))  # Unified dashboard
        flash('Invalid username or password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():  # Form validation passed
        username = form.username.data
        email = form.email.data
        password = form.password.data
        role = form.role.data

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please use a different email.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password, role=role)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error during registration: {str(e)}', 'danger')
    else:
        # Debugging logs
        print("Form Data:", form.data)
        print("Form Errors:", form.errors)

        flash('There were errors in your form submission. Please fix them.', 'danger')

    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()  # This logs out the user
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))  # Redirect to login page after logging out

@app.route('/dashboard')
@login_required
def dashboard():
    users = None
    if current_user.role == 'admin':
        users = User.query.all()  # Admin can view all users
    return render_template('dashboard.html', user=current_user, users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied! Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    if user.role == 'admin':  # Prevent deletion of other admin accounts
        flash('Cannot delete another admin account!', 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data

        # Validate username
        if username and username != current_user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username is already taken. Please choose a different one.', 'danger')
                return redirect(url_for('update_profile'))
            current_user.username = username

        # Validate email
        if email and email != current_user.email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email is already registered. Please use a different one.', 'danger')
                return redirect(url_for('update_profile'))
            current_user.email = email

        # Handle profile picture upload
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']
            if profile_pic and allowed_file(profile_pic.filename):
                filename = secure_filename(profile_pic.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_pic.save(filepath)
                current_user.profile_pic = filename
            elif profile_pic.filename != '':  # Handle invalid file format
                flash('Invalid file format. Please upload an image file (png, jpg, jpeg, gif).', 'danger')
                return redirect(url_for('update_profile'))

        # Commit the changes to the database
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('update_profile.html', user=current_user, form=form)

# Add a profile route to handle redirects to update profile (if needed)
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return redirect(url_for('update_profile'))  # Redirect to the profile update page

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates the tables if they don't already exist (use in production)
    app.run(debug=True)
