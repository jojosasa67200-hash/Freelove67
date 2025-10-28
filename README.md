python -m venv venv
source venv/bin/activate   # mac/linux
venv\Scripts\activate      # windows
{% extends "base.html" %}
{% block content %}
<h1>Personnes près de toi</h1>
<div class="row">
  {% for u in users %}
    <div class="col-md-4">
      <div class="card mb-3">
        {% if u.photo %}
          <img src="{{ url_for('uploaded_file', filename=u.photo) }}" class="card-img-top" alt="photo">
        {% endif %}
        <div class="card-body">
          <h5 class="card-title">{{ u.pseudo or 'Utilisateur' }}</h5>
          <p class="card-text">{{ u.city or '' }}</p>
          <p class="card-text">{{ (u.bio[:100] + '...') if u.bio else '' }}</p>
          <a class="btn btn-sm btn-primary" href="{{ url_for('profile', user_id=u.id) }}">Voir</a>
        </div>
      </div>
    </div>
  {% endfor %}
</div>
{% endblock %}
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rencontres Locales</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light mb-3">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('index') }}">Rencontres Locales</a>
    <div>
      {% if current_user.is_authenticated %}
        <a class="btn btn-outline-primary btn-sm" href="{{ url_for('me') }}">Mon profil</a>
        <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('logout') }}">Déconnexion</a>
      {% else %}
        <a class="btn btn-primary btn-sm" href="{{ url_for('login') }}">Connexion</a>
        <a class="btn btn-success btn-sm" href="{{ url_for('register') }}">Inscription</a>
      {% endif %}
    </div>
  </div>
</nav>
<div class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for cat, msg in messages %}
        <div class="alert alert-{{ cat }}">{{ msg }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>
</body>
</html>
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Optional

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=8)])
    pseudo = StringField('Pseudo', validators=[Optional(), Length(max=50)])
    city = StringField('Ville / CP', validators=[Optional(), Length(max=100)])
    submit = SubmitField('Créer')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

class ProfileForm(FlaskForm):
    pseudo = StringField('Pseudo', validators=[Optional(), Length(max=50)])
    city = StringField('Ville / CP', validators=[Optional(), Length(max=100)])
    bio = TextAreaField('Bio', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Enregistrer')
import sqlite3
from sqlite3 import Connection
import bcrypt

DB = 'dating.db'

def get_conn() -> Connection:
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      pseudo TEXT,
      city TEXT,
      bio TEXT,
      photo TEXT
    )
    """)
    conn.commit()
    conn.close()

def create_user(email, password, pseudo=None, city=None):
    pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_conn()
    conn.execute("INSERT INTO users (email, password_hash, pseudo, city) VALUES (?, ?, ?, ?)",
                 (email, pw, pseudo, city))
    conn.commit()
    conn.close()

def get_user_by_email(email):
    conn = get_conn()
    r = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return dict(r) if r else None

def get_user_by_id(uid):
    conn = get_conn()
    r = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return dict(r) if r else None

def verify_user_credentials(email, password):
    u = get_user_by_email(email)
    if not u:
        return None
    if bcrypt.checkpw(password.encode(), u['password_hash'].encode()):
        return u
    return None

def update_profile(user_id, pseudo, city, bio, photo_filename=None):
    conn = get_conn()
    if photo_filename:
        conn.execute("UPDATE users SET pseudo=?, city=?, bio=?, photo=? WHERE id=?",
                     (pseudo, city, bio, photo_filename, user_id))
    else:
        conn.execute("UPDATE users SET pseudo=?, city=?, bio=? WHERE id=?",
                     (pseudo, city, bio, user_id))
    conn.commit()
    conn.close()

def list_local_users(current_user_id=None, limit=50):
    conn = get_conn()
    if current_user_id:
        rows = conn.execute("SELECT id, pseudo, city, bio, photo FROM users WHERE id != ? LIMIT ?",
                            (current_user_id, limit)).fetchall()
    else:
        rows = conn.execute("SELECT id, pseudo, city, bio, photo FROM users LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
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
