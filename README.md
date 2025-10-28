freelove67/
├─ app.py
├─ requirements.txt
├─ README.md
├─ templates/
│  └─ index.html
├─ static/
│  └─ style.css
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
gunicorn==21.2.0
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>FreeLove67 💘</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <h1>Bienvenue sur FreeLove67 💕</h1>
  <p>Ton site de rencontres local en Alsace est en ligne !</p>
</body>
</html>
body {
  background-color: #fff0f5;
  color: #333;
  font-family: Arial, sans-serif;
  text-align: center;
  padding: 50px;
}
h1 {
  color: #ff4f8b;
}
# 💘 FreeLove67

Un site de rencontres local (Alsace) développé avec Flask.

## 🚀 Lancer en local

```bash
pip install -r requirements.txt
python app.py
