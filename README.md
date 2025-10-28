#Freelove67
site de rencontre
freelove67/
├─ app.py
├─ models.py
├─ forms.py
├─ requirements.txt
├─ Dockerfile
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
│  └─ style.css
├─ uploads/
└─ instance/
   └─ config.env  (optionnel)
from flask import Flask, render_template
import os

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

Flask==3.0.3
Flask-Login==0.6.3
Flask-WTF==1.1.1
Flask-Limiter==2.9.0
bcrypt==4.0.1
python-dotenv==1.0.0
gunicorn==21.2.0
Jinja2==3.1.3
Werkzeug==3.0.2
itsdangerous==2.2.0
# Image de base
FROM python:3.12-slim

# Dossier de travail
WORKDIR /app

# Copie du projet
COPY . .

# Installation des dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Variables d'environnement Flask
ENV FLASK_APP=app.py

# Port exposé
EXPOSE 10000

# Commande de démarrage
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "app:app"]
# 💘 FreeLove67 — Rencontres locales (Alsace)

Application Flask simple avec profils, messagerie et compatibilité locale.

## 🚀 Lancement local

```bash
pip install -r requirements.txt
python app.py
pip install -r requirements.txt
gunicorn app:app
{% extends "base.html" %}
{% block title %}Accueil - FreeLove67{% endblock %}
{% block content %}
  <h2>Bienvenue sur FreeLove67 💞</h2>
  <p>Rencontrez des personnes proches de vous en Alsace.</p>
{% endblock %}
body {
  font-family: Arial, sans-serif;
  background-color: #fff0f5;
  color: #333;
  text-align: center;
  padding: 40px;
}

header {
  background: #ff7fa3;
  color: white;
  padding: 10px;
  border-radius: 10px;
}

nav a {
  color: white;
  margin: 0 10px;
  text-decoration: none;
  font-weight: bold;
}
