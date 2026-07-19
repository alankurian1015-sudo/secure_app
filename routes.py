from flask import render_template, redirect, url_for, flash, session, request
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, login_manager
from models import User, AuditLog
from forms import SignupForm, LoginForm, Verify2FAForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import bleach
import pyotp
import segno
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


def log_event(event_type, user_id=None, username=None):
    ip_address = request.remote_addr or 'Unknown'
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    log = AuditLog(
        user_id=user_id,
        username=username,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.session.add(log)
    db.session.commit()


@app.before_request
def check_session_pinning():
    # Skip static files
    if request.path.startswith('/static/'):
        return
        
    if current_user.is_authenticated:
        cached_ip = session.get('client_ip')
        cached_ua = session.get('user_agent')
        
        current_ip = request.remote_addr
        current_ua = request.headers.get('User-Agent', 'Unknown')
        
        if cached_ip != current_ip or cached_ua != current_ua:
            log_event('session_anomaly_hijack', user_id=current_user.id, username=current_user.username)
            logout_user()
            session.clear()
            flash('Your session has been terminated due to a change in IP or browser details. Please log in again.', 'danger')
            return redirect(url_for('login'))


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
            log_event('registration_attempt_failed', username=username)
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

        log_event('user_registration', user_id=new_user.id, username=new_user.username)
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
                log_event('auto_unlock', user_id=user.id, username=user.username)
                flash('Account unlocked. Please try again.', 'success')
            else:
                # Still locked — show remaining time
                remaining = 900 - int(time_locked.total_seconds())
                minutes = remaining // 60
                seconds = remaining % 60
                log_event('login_attempt_locked_user', user_id=user.id, username=user.username)
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
            if user.is_totp_enabled:
                # Redirect to 2FA verification step without logging in yet
                session['temp_user_id'] = user.id
                return redirect(url_for('verify_2fa'))

            user.failed_attempts = 0
            user.locked_at = None
            db.session.commit()
            
            login_user(user)
            session.permanent = True
            session['client_ip'] = request.remote_addr
            session['user_agent'] = request.headers.get('User-Agent', 'Unknown')
            
            log_event('login_success', user_id=user.id, username=user.username)
            return redirect(url_for('dashboard'))
        else:
            if user and not user.is_locked:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.is_locked = True
                    user.locked_at = datetime.utcnow()  # ← save lock time
                    log_event('account_lockout', user_id=user.id, username=user.username)
                    flash(
                        'Account locked for 15 minutes due to too '
                        'many failed attempts.', 'danger'
                    )
                else:
                    log_event('login_failed', user_id=user.id, username=user.username)
                    flash(
                        f'Invalid credentials. {5 - user.failed_attempts} '
                        'attempts remaining.', 'danger'
                    )
                db.session.commit()
            elif not user:
                log_event('login_failed', username=username)
                flash('Invalid credentials.', 'danger')

    return render_template('login.html', form=form)


@app.route('/login/2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_2fa():
    temp_user_id = session.get('temp_user_id')
    if not temp_user_id:
        return redirect(url_for('login'))

    user = db.session.get(User, temp_user_id)
    if not user or not user.is_totp_enabled:
        session.pop('temp_user_id', None)
        return redirect(url_for('login'))

    form = Verify2FAForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(form.code.data.strip(), valid_window=1):
            user.failed_attempts = 0
            user.locked_at = None
            db.session.commit()

            login_user(user)
            session.permanent = True
            session['client_ip'] = request.remote_addr
            session['user_agent'] = request.headers.get('User-Agent', 'Unknown')
            session.pop('temp_user_id', None)

            log_event('login_success_2fa', user_id=user.id, username=user.username)
            return redirect(url_for('dashboard'))
        else:
            log_event('2fa_code_failed', user_id=user.id, username=user.username)
            flash('Invalid verification code. Please try again.', 'danger')

    return render_template('verify_2fa.html', form=form)


# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', username=current_user.username, audit_logs=logs)


# Enable 2FA Setup
@app.route('/setup/2fa', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute")
def setup_2fa():
    if current_user.is_totp_enabled:
        flash('2FA is already enabled.', 'info')
        return redirect(url_for('dashboard'))

    secret = session.get('totp_secret')
    if not secret:
        secret = pyotp.random_base32()
        session['totp_secret'] = secret

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="SecureAuth"
    )

    qr = segno.make(provisioning_uri)
    qr_svg = qr.svg_inline(scale=4)

    form = Verify2FAForm()
    if form.validate_on_submit():
        if totp.verify(form.code.data.strip(), valid_window=1):
            current_user.totp_secret = secret
            current_user.is_totp_enabled = True
            db.session.commit()
            session.pop('totp_secret', None)

            log_event('2fa_enabled', user_id=current_user.id, username=current_user.username)
            flash('Two-factor authentication successfully enabled!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')

    return render_template('setup_2fa.html', form=form, qr_svg=qr_svg, secret=secret)


# Disable 2FA
@app.route('/disable/2fa', methods=['POST'])
@login_required
def disable_2fa():
    if not current_user.is_totp_enabled:
        flash('2FA is not enabled.', 'info')
        return redirect(url_for('dashboard'))

    current_user.totp_secret = None
    current_user.is_totp_enabled = False
    db.session.commit()

    log_event('2fa_disabled', user_id=current_user.id, username=current_user.username)
    flash('Two-factor authentication has been disabled.', 'success')
    return redirect(url_for('dashboard'))


# Logout
@app.route('/logout')
@login_required
def logout():
    log_event('logout', user_id=current_user.id, username=current_user.username)
    logout_user()
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

