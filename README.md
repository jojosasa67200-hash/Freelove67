import os
from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from models import init_db, get_user_by_email, create_user, verify_user_credentials, get_user_by_id, update_profile, list_local_users
from forms import RegistrationForm, LoginForm, ProfileForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXT = {'png', 'jpg', 'jpeg'}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Rate limiting
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# init DB (creates file if not exists)
init_db()

# Simple user class for Flask-Login
class UserObj:
    def __init__(self, id, email):
        self.id = id
        self.email = email

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    u = get_user_by_id(int(user_id))
    if not u:
        return None
    return UserObj(u['id'], u['email'])

@app.route('/')
def index():
    users = []
    if current_user.is_authenticated:
        users = list_local_users(current_user_id=int(current_user.get_id()))
    return render_template('index.html', users=users)

@app.route('/register', methods=['GET','POST'])
@limiter.limit("10 per hour")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if get_user_by_email(form.email.data):
            flash('Email déjà utilisé.', 'danger')
            return redirect(url_for('register'))
        create_user(form.email.data, form.password.data, form.pseudo.data, form.city.data)
        flash('Compte créé. Connecte-toi.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
@limiter.limit("20 per hour")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = verify_user_credentials(form.email.data, form.password.data)
        if user:
            login_user(UserObj(user['id'], user['email']))
            flash('Connecté.', 'success')
            return redirect(url_for('index'))
        flash('Email ou mot de passe invalide.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Déconnecté.', 'info')
    return redirect(url_for('index'))

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    u = get_user_by_id(user_id)
    if not u:
        abort(404)
    return render_template('profile.html', u=u)

@app.route('/me', methods=['GET','POST'])
@login_required
def me():
    u = get_user_by_id(int(current_user.get_id()))
    form = ProfileForm(obj=u)
    if form.validate_on_submit():
        filename = None
        file = request.files.get('photo')
        if file and file.filename:
            ext = file.filename.rsplit('.', 1)[-1].lower()
            if ext not in ALLOWED_EXT:
                flash('Format d\'image non autorisé.', 'danger')
                return redirect(url_for('me'))
            filename = secure_filename(f"{current_user.get_id()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        update_profile(current_user.get_id(), form.pseudo.data, form.city.data, form.bio.data, filename)
        flash('Profil mis à jour.', 'success')
        return redirect(url_for('me'))
    return render_template('profile.html', form=form, u=u)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)  # ssl_context adhoc pour HTTPS local
Flask==2.3.2
Flask-Login==0.6.3
Flask-WTF==1.1.1
bcrypt==4.0.1
Flask-Limiter==2.9.0
python-dotenv==1.0.0
dating-app/
├─ app.py
├─ models.py
├─ forms.py
├─ requirements.txt
├─ templates/
│  ├─ base.html
│  ├─ index.html
│  ├─ register.html
│  ├─ login.html
│  ├─ profile.html
├─ static/
│  └─ (css/js si besoin)
├─ uploads/
└─ instance/
   └─ config.env   (optionnel)
# Freelove67
Site de rencontre en alsace
