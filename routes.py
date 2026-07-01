from flask import render_template, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, login_manager
from models import User
from forms import SignupForm, LoginForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import bleach
from datetime import datetime


limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Session is made permanent on successful login to reduce request overhead.


# Home
@app.route('/')
def home():
    return redirect(url_for('login'))


# Signup
@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def signup():
    form = SignupForm()
    if form.validate_on_submit():

        # Sanitize inputs
        username = bleach.clean(form.username.data.strip())
        email = bleach.clean(form.email.data.strip())

        # Check if username or email already exists (single query optimization)
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            if existing_user.username == username:
                flash(
                    'Username already taken. Please choose another.', 'danger'
                )
            else:
                flash('Email already registered.', 'danger')
            return redirect(url_for('signup'))

        # Hash password
        hashed_password = bcrypt.hashpw(
            form.password.data.encode('utf-8'),
            bcrypt.gensalt()
        )

        # Save user (Pythonic instantiation)
        new_user = User(
            username=username,
            email=email,
            password=hashed_password.decode('utf-8')
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():

        username = bleach.clean(form.username.data.strip())
        user = User.query.filter_by(username=username).first()

        # Check if account is locked
        if user and user.is_locked:
            # Check if 15 minutes have passed since locking
            time_locked = datetime.utcnow() - user.locked_at
            if time_locked.total_seconds() >= 900:  # 900 seconds = 15 minutes
                # Auto unlock
                user.is_locked = False
                user.failed_attempts = 0
                user.locked_at = None
                db.session.commit()
                flash('Account unlocked. Please try again.', 'success')
            else:
                # Still locked — show remaining time
                remaining = 900 - int(time_locked.total_seconds())
                minutes = remaining // 60
                seconds = remaining % 60
                flash(
                    f'Account locked. Try again in {minutes}m {seconds}s.',
                    'danger'
                )
                return redirect(url_for('login'))

        # Check password with timing attack mitigation
        password_correct = False
        if user and not user.is_locked:
            password_correct = bcrypt.checkpw(
                form.password.data.encode('utf-8'),
                user.password.encode('utf-8')
            )
        else:
            # Run dummy bcrypt check if user is not found to prevent
            # timing-based user enumeration
            if not user:
                dummy_hash = (
                    b'$2b$12$kbB9G5f51XU8h17D7D.'
                    b'Wc.e.Zp0B2c81K.Yy.Y.Y.Y.Y.Y.Y.Y.Y.'
                )
                bcrypt.checkpw(form.password.data.encode('utf-8'), dummy_hash)

        if password_correct:
            user.failed_attempts = 0
            user.locked_at = None
            db.session.commit()
            login_user(user)
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            if user and not user.is_locked:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.is_locked = True
                    user.locked_at = datetime.utcnow()  # ← save lock time
                    flash(
                        'Account locked for 15 minutes due to too '
                        'many failed attempts.', 'danger'
                    )
                else:
                    flash(
                        f'Invalid credentials. {5 - user.failed_attempts} '
                        'attempts remaining.', 'danger'
                    )
                db.session.commit()
            elif not user:
                flash('Invalid credentials.', 'danger')

    return render_template('login.html', form=form)


# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)


# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))
