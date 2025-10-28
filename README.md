#Freelove67
site de rencontre
freelove67/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── index.html
│   ├── login.html
│   └── profile.html
├── static/
│   ├── style.css
│   └── script.js
└── uploads/
from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def home():
    return "FreeLove fonctionne 🎉"

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
Flask==3.0.3
gunicorn==21.2.0
Jinja2==3.1.3
Werkzeug==3.0.2
itsdangerous==2.2.0
# 💘 FreeLove — Site de rencontres locales (Alsace)

Petit site de test basé sur Flask pour un déploiement Render.

## 🚀 Installation locale

```bash
pip install -r requirements.txt
python app.py
pip install -r requirements.txt
gunicorn app:app

---

### 🖼️ 4️⃣ `templates/index.html`

```html
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>FreeLove - Accueil</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <h1>Bienvenue sur FreeLove 💘</h1>
  <p>Votre site de rencontres locales en Alsace.</p>
</body>
</html>
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Connexion - FreeLove</title>
</head>
<body>
  <h1>Connexion</h1>
  <form>
    <input type="text" placeholder="Nom d'utilisateur">
    <input type="password" placeholder="Mot de passe">
    <button>Se connecter</button>
  </form>
</body>
</html>
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Profil - FreeLove</title>
</head>
<body>
  <h1>Profil utilisateur</h1>
  <p>Ici s’afficheront les informations du profil.</p>
</body>
</html>
body {
  font-family: Arial, sans-serif;
  text-align: center;
  background-color: #fff0f5;
  color: #333;
  margin: 0;
  padding: 50px;
}

h1 {
  color: #e75480;
}
// Script FreeLove (vide pour le moment)
console.log("FreeLove chargé !");
