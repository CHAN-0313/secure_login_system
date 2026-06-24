import os, pyotp, qrcode, io, base64
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
from werkzeug.security import generate_password_hash, check_password_hash

os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database'), exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret-key')
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'app.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

MAX_ATTEMPTS = 5
LOCK_MINUTES = 15
PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'

# ---------- MODELS ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    twofa_secret = db.Column(db.String(32))
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_activity(user_id, action):
    db.session.add(ActivityLog(user_id=user_id, action=action, ip_address=request.remote_addr))
    db.session.commit()

# ---------- FORMS ----------
class RegisterForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Regexp(
        PASSWORD_REGEX, message="Min 8 chars, with upper, lower, number & special char")])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OTPForm(FlaskForm):
    otp = StringField('6-digit Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

# ---------- ROUTES ----------
@app.route('/')
def home():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html', form=form)
        user = User(full_name=form.full_name.data,
                    email=form.email.data.lower(),
                    password_hash=generate_password_hash(form.password.data))
        db.session.add(user)
        db.session.commit()
        log_activity(user.id, 'Registration')
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            flash(f'Account locked. Try again after {user.locked_until.strftime("%H:%M:%S")}.', 'danger')
            return render_template('login.html', form=form)

        if user and check_password_hash(user.password_hash, form.password.data):
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()
            if user.is_2fa_enabled:
                session['pre_2fa_user_id'] = user.id
                return redirect(url_for('verify_2fa'))
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            log_activity(user.id, 'Login')
            return redirect(url_for('dashboard'))
        else:
            if user:
                user.failed_attempts += 1
                log_activity(user.id, 'Failed Login')
                if user.failed_attempts >= MAX_ATTEMPTS:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)
                    flash('Too many failed attempts. Account locked 15 minutes.', 'danger')
                else:
                    flash(f'Invalid credentials. {MAX_ATTEMPTS - user.failed_attempts} attempts left.', 'danger')
                db.session.commit()
            else:
                flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    form = OTPForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.twofa_secret)
        if totp.verify(form.otp.data):
            session.pop('pre_2fa_user_id', None)
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            log_activity(user.id, 'Login (2FA)')
            return redirect(url_for('dashboard'))
        flash('Invalid OTP code.', 'danger')
    return render_template('verify_2fa.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    total_logins = ActivityLog.query.filter_by(user_id=current_user.id, action='Login').count() + \
                   ActivityLog.query.filter_by(user_id=current_user.id, action='Login (2FA)').count()
    last_log = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).first()
    score = 50 + (30 if current_user.is_2fa_enabled else 0) + 20
    return render_template('dashboard.html', total_logins=total_logins, last_log=last_log, score=score)

@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if not current_user.twofa_secret:
        current_user.twofa_secret = pyotp.random_base32()
        db.session.commit()
    totp = pyotp.TOTP(current_user.twofa_secret)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name="SecureLoginApp")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    form = OTPForm()
    if form.validate_on_submit():
        if totp.verify(form.otp.data):
            current_user.is_2fa_enabled = True
            db.session.commit()
            log_activity(current_user.id, '2FA Enable')
            flash('2FA enabled successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid code, try again.', 'danger')
    return render_template('setup_2fa.html', qr_b64=qr_b64, form=form)

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    current_user.is_2fa_enabled = False
    current_user.twofa_secret = None
    db.session.commit()
    log_activity(current_user.id, '2FA Disable')
    flash('2FA disabled.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/activity-logs')
@login_required
def activity_logs():
    logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(50).all()
    return render_template('activity_logs.html', logs=logs)

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'Logout')
    logout_user()
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
