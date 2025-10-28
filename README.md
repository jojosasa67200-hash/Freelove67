#Freelove67
site de rencontre
freelove67/
├─ app.py
├─ models.py
├─ forms.py
├─ requirements.txt
├─ Dockerfile
├─ docker-compose.yml
├─ README.md
├─ templates/
│  ├─ base.html
│  ├─ index.html
│  ├─ register.html
│  ├─ login.html
│  ├─ edit_profile.html
│  ├─ profile.html
│  ├─ search.html
│  ├─ messages.html
│  └─ inbox.html
├─ static/
│  └─ (vide ou CSS personnalisé)
├─ uploads/
└─ instance/
   └─ config.env  (optionnel pour variables)
Flask==2.3.2
Flask-Login==0.6.3
Flask-WTF==1.1.1
bcrypt==4.0.1
Flask-Limiter==2.9.0
python-dotenv==1.0.0
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "FreeLove fonctionne 🎉"

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
import sqlite3
from sqlite3 import Connection
import bcrypt
from datetime import datetime

DB = 'freelove.db'

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
      photo TEXT,
      age INTEGER,
      gender TEXT,
      pref_gender TEXT,
      interests TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_id INTEGER NOT NULL,
      to_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(from_id,to_id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS matches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user1 INTEGER NOT NULL,
      user2 INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(user1,user2)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      match_id INTEGER NOT NULL,
      from_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

# Basic user functions
def create_user(email, password, pseudo=None, city=None, age=None, gender=None, pref_gender=None, interests=None):
    pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_conn()
    conn.execute("""
      INSERT INTO users (email, password_hash, pseudo, city, age, gender, pref_gender, interests)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      """, (email, pw, pseudo, city, age, gender, pref_gender, interests))
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

def update_profile(user_id, pseudo, city, bio, photo=None, age=None, gender=None, pref_gender=None, interests=None):
    conn = get_conn()
    if photo:
        conn.execute("""
            UPDATE users SET pseudo=?, city=?, bio=?, photo=?, age=?, gender=?, pref_gender=?, interests=? WHERE id=?
        """, (pseudo, city, bio, photo, age, gender, pref_gender, interests, user_id))
    else:
        conn.execute("""
            UPDATE users SET pseudo=?, city=?, bio=?, age=?, gender=?, pref_gender=?, interests=? WHERE id=?
        """, (pseudo, city, bio, age, gender, pref_gender, interests, user_id))
    conn.commit()
    conn.close()

def list_local_users(current_user_id=None, limit=50):
    conn = get_conn()
    if current_user_id:
        rows = conn.execute("SELECT id, pseudo, city, bio, photo FROM users WHERE id != ? AND city LIKE '%Alsace%' LIMIT ?", (current_user_id, limit)).fetchall()
    else:
        rows = conn.execute("SELECT id, pseudo, city, bio, photo FROM users WHERE city LIKE '%Alsace%' LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def list_users_filtered(current_user_id=None, city=None, interests=None):
    conn = get_conn()
    q = "SELECT id, pseudo, city, bio, photo FROM users WHERE id != ?"
    params = [current_user_id]
    if city:
        q += " AND city LIKE ?"
        params.append(f"%{city}%")
    if interests:
        # naive interests filter: any of comma parts
        parts = [p.strip() for p in interests.split(',') if p.strip()]
        if parts:
            q += " AND (" + " OR ".join(["interests LIKE ?"]*len(parts)) + ")"
            for p in parts:
                params.append(f"%{p}%")
    q += " LIMIT 200"
    rows = conn.execute(q, tuple(params)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Likes
def like_user(from_id, to_id):
    conn = get_conn()
    try:
        conn.execute("INSERT INTO likes (from_id, to_id, created_at) VALUES (?, ?, ?)",
                     (from_id, to_id, datetime.utcnow().isoformat()))
        conn.commit()
    except Exception:
        pass
    conn.close()

def get_like(from_id, to_id):
    conn = get_conn()
    r = conn.execute("SELECT * FROM likes WHERE from_id=? AND to_id=?", (from_id, to_id)).fetchone()
    conn.close()
    return dict(r) if r else None

def mutual_like_exists(a,b):
    return bool(get_like(a,b)) and bool(get_like(b,a))

# Points logic
def compute_points_between(user_a_id, user_b_id):
    a = get_user_by_id(user_a_id)
    b = get_user_by_id(user_b_id)
    if not a or not b:
        return 0
    points = 0
    # city exact or contains Alsace both -> 3
    if a.get('city') and b.get('city') and a['city'].lower() == b['city'].lower():
        points += 3
    # age within 5 years -> 2
    try:
        if a.get('age') and b.get('age') and abs(int(a['age']) - int(b['age'])) <= 5:
            points += 2
    except Exception:
        pass
    # shared interests: each shared interest = 2 points
    ai = set([s.strip().lower() for s in (a.get('interests') or "").split(',') if s.strip()])
    bi = set([s.strip().lower() for s in (b.get('interests') or "").split(',') if s.strip()])
    shared = ai.intersection(bi)
    points += 2 * len(shared)
    # gender preference alignment: if each pref includes other's gender -> +3
    if a.get('pref_gender') and b.get('gender') and b['gender'].lower() in (a['pref_gender'].lower() or ""):
        points += 3
    if b.get('pref_gender') and a.get('gender') and a['gender'].lower() in (b['pref_gender'].lower() or ""):
        points += 0  # avoid double-counting; already checked above
    return points

# Matches
def create_match_if_eligible(from_id, to_id):
    # if reciprocal like AND points >= 10 -> create match
    if not mutual_like_exists(from_id, to_id):
        return False
    pts = compute_points_between(from_id, to_id)
    if pts < 10:
        return False
    # ensure ordering to avoid duplicate (small id first)
    u1, u2 = sorted((from_id, to_id))
    conn = get_conn()
    exists = conn.execute("SELECT * FROM matches WHERE user1=? AND user2=?", (u1, u2)).fetchone()
    if exists:
        conn.close()
        return True
    conn.execute("INSERT INTO matches (user1, user2, created_at) VALUES (?, ?, ?)", (u1, u2, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return True

def get_matches_for_user(user_id):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM matches WHERE user1=? OR user2=?", (user_id, user_id)).fetchall()
    matches = []
    for r in rows:
        other = r['user1'] if r['user2'] == user_id else r['user2']
        matches.append({"match_id": r['id'], "other_id": other, "created_at": r['created_at']})
    conn.close()
    return matches

def get_match(match_id):
    conn = get_conn()
    r = conn.execute("SELECT * FROM matches WHERE id=?", (match_id,)).fetchone()
    conn.close()
    return dict(r) if r else None

def get_match_between(a,b):
    u1, u2 = sorted((a,b))
    conn = get_conn()
    r = conn.execute("SELECT * FROM matches WHERE user1=? AND user2=?", (u1, u2)).fetchone()
    conn.close()
    return dict(r) if r else None

# Messages
def create_message(match_id, from_id, content):
    conn = get_conn()
    conn.execute("INSERT INTO messages (match_id, from_id, content, created_at) VALUES (?, ?, ?, ?)",
                 (match_id, from_id, content, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def get_messages_for_match(match_id):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM messages WHERE match_id=? ORDER BY created_at ASC", (match_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, SelectField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=8)])
    pseudo = StringField('Pseudo', validators=[Optional(), Length(max=50)])
    city = StringField('Ville / CP (ex: Strasbourg, Alsace)', validators=[Optional(), Length(max=100)])
    age = IntegerField('Âge', validators=[Optional(), NumberRange(min=18, max=120)])
    gender = SelectField('Genre', choices=[('Homme','Homme'),('Femme','Femme'),('Autre','Autre')])
    pref_gender = SelectField('Préférence', choices=[('Homme','Homme'),('Femme','Femme'),('Tous','Tous')])
    interests = StringField('Centres d\'intérêt (séparés par des virgules)', validators=[Optional(), Length(max=200)])
    submit = SubmitField('Créer')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

class ProfileForm(FlaskForm):
    pseudo = StringField('Pseudo', validators=[Optional(), Length(max=50)])
    city = StringField('Ville / CP', validators=[Optional(), Length(max=100)])
    bio = TextAreaField('Bio', validators=[Optional(), Length(max=500)])
    age = IntegerField('Âge', validators=[Optional(), NumberRange(min=18, max=120)])
    gender = SelectField('Genre', choices=[('Homme','Homme'),('Femme','Femme'),('Autre','Autre')])
    pref_gender = SelectField('Préférence', choices=[('Homme','Homme'),('Femme','Femme'),('Tous','Tous')])
    interests = StringField('Centres d\'intérêt (séparés par des virgules)', validators=[Optional(), Length(max=200)])
    submit = SubmitField('Enregistrer')

class SearchForm(FlaskForm):
    city = StringField('Ville', validators=[Optional(), Length(max=100)])
    interests = StringField('Centres d\'intérêt (ex: randonnée, musique)', validators=[Optional(), Length(max=200)])
    submit = SubmitField('Rechercher')

class MessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Envoyer')
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Freelove - Rencontres Alsace</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light mb-3">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('index') }}">Freelove (Alsace)</a>
    <div>
      {% if current_user.is_authenticated %}
        <a class="btn btn-outline-primary btn-sm" href="{{ url_for('me') }}">Mon profil</a>
        <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('search') }}">Recherche</a>
        <a class="btn btn-success btn-sm" href="{{ url_for('matches') }}">Messages</a>
        <a class="btn btn-danger btn-sm" href="{{ url_for('logout') }}">Déconnexion</a>
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
{% extends "base.html" %}
{% block content %}
<h1>Bienvenue sur Freelove — Alsace</h1>
{% if current_user.is_authenticated %}
  <p>Personnes proches :</p>
  <div class="row">
    {% for u in users %}
      <div class="col-md-4">
        <div class="card mb-3">
          {% if u.photo %}
            <img src="{{ url_for('uploaded_file', filename=u.photo) }}" class="card-img-top" style="max-height:200px;object-fit:cover;">
          {% endif %}
          <div class="card-body">
            <h5 class="card-title">{{ u.pseudo or 'Utilisateur' }}</h5>
            <p class="card-text">{{ u.city or '' }}</p>
            <a class="btn btn-sm btn-primary" href="{{ url_for('profile', user_id=u.id) }}">Voir</a>
          </div>
        </div>
      </div>
    {% endfor %}
  </div>
{% else %}
  <p>Inscris-toi pour rencontrer des personnes en Alsace.</p>
{% endif %}
{% endblock %}
{% extends "base.html" %}
{% block content %}
<h2>Inscription</h2>
<form method="post">
  {{ form.hidden_tag() }}
  <div class="mb-3">{{ form.email.label }} {{ form.email(class="form-control") }}</div>
  <div class="mb-3">{{ form.password.label }} {{ form.password(class="form-control") }}</div>
  <div class="mb-3">{{ form.pseudo.label }} {{ form.pseudo(class="form-control") }}</div>
  <div class="mb-3">{{ form.city.label }} {{ form.city(class="form-control") }}</div>
  <div class="mb-3">{{ form.age.label }} {{ form.age(class="form-control") }}</div>
  <div class="mb-3">{{ form.gender.label }} {{ form.gender(class="form-select") }}</div>
  <div class="mb-3">{{ form.pref_gender.label }} {{ form.pref_gender(class="form-select") }}</div>
  <div class="mb-3">{{ form.interests.label }} {{ form.interests(class="form-control") }}</div>
  {{ form.submit(class="btn btn-success") }}
</form>
{% endblock %}
{% extends "base.html" %}
{% block content %}
<h2>Connexion</h2>
<form method="post">
  {{ form.hidden_tag() }}
  <div class="mb-3">{{ form.email.label }} {{ form.email(class="form-control") }}</div>
  <div class="mb-3">{{ form.password.label }} {{ form.password(class="form-control") }}</div>
  {{ form.submit(class="btn btn-primary") }}
</form>
{% endblock %}
{% extends "base.html" %}
{% block content %}
<h2>Mon profil</h2>
<form method="post" enctype="multipart/form-data">
  {{ form.hidden_tag() }}
  <div class="mb-3">{{ form.pseudo.label }} {{ form.pseudo(class="form-control") }}</div>
  <div class="mb-3">{{ form.city.label }} {{ form.city(class="form-control") }}</div>
  <div class="mb-3">{{ form.age.label }} {{ form.age(class="form-control") }}</div>
  <div class="mb-3">{{ form.gender.label }} {{ form.gender(class="form-select") }}</div>
  <div class="mb-3">{{ form.pref_gender.label }} {{ form.pref_gender(class="form-select") }}</div>
  <div class="mb-3">{{ form.interests.label }} {{ form.interests(class="form-control") }}</div>
  <div class="mb-3">{{ form.bio.label }} {{ form.bio(class="form-control") }}</div>
  <div class="mb-3">
    <label for="photo">Photo (jpg/png, max 2MB)</label>
    <input type="file" name="photo" class="form-control" accept=".jpg,.jpeg,.png">
  </div>
  {{ form.submit(class="btn btn-success") }}
</form>
{% endblock %}
{% extends "base.html" %}
{% block content %}
<h2>Profil de {{ u.pseudo or 'Utilisateur' }}</h2>
<p>Ville : {{ u.city or '—' }} {% if u.age %} • Âge : {{ u.age }}{% endif %}</p>
<p>{{ u.bio or '' }}</p>

{% if can_see_photo and u.photo %}
  <img src="{{ url_for('uploaded_file', filename=u.photo) }}" style="max-width:300px;">
{% else %}
  <div class="alert alert-info">
    La photo est masquée — il faut atteindre <strong>10 points en commun</strong> ET un like réciproque pour créer un match et révéler la photo.
  </div>
{% endif %}

<form id="like-form" method="post" action="{{ url_for('like', user_id=u.id) }}">
  <button type="submit" class="btn btn-primary">Like</button>
</form>

{% endblock %}
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]
version: '3.8'
services:
  web:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - .:/app
      - ./uploads:/app/uploads
    environment:
      - SECRET_KEY=change-me
python -m venv venv
# mac/linux
source venv/bin/activate
# windows
venv\Scripts\activate
pip install -r requirements.txt
python app.py
docker-compose up --build
# puis ouvrir http://127.0.0.1:5000 (ou https si tu veux config)
# ❤️ FreeLove — Site de rencontres locales en Alsace

**FreeLove** est une plateforme de rencontres **gratuite, locale et sécurisée**, conçue pour favoriser des connexions authentiques entre les habitants d’Alsace.  
Aucune photo avant le *match* : les profils sont basés sur les **points communs** et la compatibilité avant tout.

---

## 🚀 Fonctionnalités principales

- 🔐 **Inscription / Connexion sécurisée** (mots de passe chiffrés avec bcrypt)
- 🧑‍🤝‍🧑 **Profils complets** (pseudo, bio, ville, centres d’intérêt)
- 🌍 **Recherche locale** : rencontrez des utilisateurs proches (Alsace)
- 💬 **Messagerie privée** entre profils qui matchent
- ❤️ **Système de "likes" et compatibilité**
- 🎯 **Match automatique** dès 10 points communs
- 🕵️‍♀️ **Anonymat avant le match** (photo cachée jusqu’à compatibilité)
- ⚙️ **Sécurité** : CSRF, rate-limiting, validation des entrées, HTTPS local

---

## 🏗️ Stack technique

- **Backend :** Flask (Python)
- **Base de données :** SQLite (local) → PostgreSQL possible en ligne
- **Frontend :** HTML + Bootstrap 5 (Jinja2 templates)
- **Auth :** Flask-Login + bcrypt
- **Formulaires :** Flask-WTF (CSRF inclus)
- **Rate limiting :** Flask-Limiter
- **Langue :** Français 🇫🇷

---

## 📦 Installation locale

### 1️⃣ Cloner le projet

```bash
git clone https://github.com/votre-utilisateur/freelove.git
cd freelove
python -m venv venv
source venv/bin/activate   # mac/linux
venv\Scripts\activate      # windows
pip install -r requirements.txt
python -c "from models import init_db; init_db()"
python app.py
freelove/
├── app.py                # Application principale Flask
├── models.py             # Base de données et fonctions utilisateur
├── forms.py              # Formulaires et validation
├── requirements.txt      # Dépendances Python
├── templates/            # Pages HTML Jinja2
├── static/               # CSS / JS / images
├── uploads/              # Photos de profils (stockage local)
└── README.md             # Ce fichier
---

Souhaites-tu que je te crée le **fichier `README.md` téléchargeable** (avec le bon encodage et format GitHub), ou veux-tu que je t’ajoute aussi un **logo + favicon FreeLove** à intégrer dans le site ?
git init
git add .
git commit -m "Initial commit FreeLove"
git branch -M main
git remote add origin https://github.com/TON_UTILISATEUR/freelove.git
git push -u origin main
git add .
git commit -m "Préparation déploiement"
git push origin main
