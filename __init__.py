from cryptography.fernet import Fernet
from flask import Flask, render_template_string, render_template, jsonify, request
from flask import render_template
from flask import json
from urllib.request import urlopen
import sqlite3

app = Flask(__name__)

# ----------- Clé fixe pour les routes classiques ----------- #
key = Fernet.generate_key()  # Tu peux remplacer par une clé fixe pendant le test
fernet = Fernet(key)

@app.route('/')
def home():
    return render_template('hello.html') 

# ----------- Exercice 1 : chiffrement / déchiffrement simple ----------- #

@app.route('/encrypt/<string:valeur>')
def encrypt(valeur):
    valeur_bytes = valeur.encode()
    token = fernet.encrypt(valeur_bytes)
    return f"Valeur chiffrée : {token.decode()}"

@app.route('/decrypt/<token>')
def decrypt(token):
    try:
        decrypted = fernet.decrypt(token.encode()).decode()
        return f"Valeur déchiffrée : {decrypted}"
    except Exception as e:
        return f"Erreur lors du déchiffrement : {str(e)}"

# ----------- Exercice 2 : avec clé personnalisée ----------- #

def is_valid_fernet_key(key_str):
    import base64
    try:
        padded = key_str + '=' * (-len(key_str) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode())
        return len(decoded) == 32
    except Exception:
        return False

@app.route('/encrypt_custom/<message>/<path:key>')
def encrypt_custom(message, key):
    if not is_valid_fernet_key(key):
        return "Erreur : clé invalide. Elle doit être en base64, 32 octets.", 400

    try:
        padded_key = key + '=' * (-len(key) % 4)
        user_fernet = Fernet(padded_key.encode())
        encrypted = user_fernet.encrypt(message.encode()).decode()
        return f"Message chiffré : {encrypted}"
    except Exception as e:
        return f"Erreur lors du chiffrement : {str(e)}"

@app.route('/decrypt_custom/<path:token>/<path:key>')
def decrypt_custom(token, key):
    if not is_valid_fernet_key(key):
        return "Erreur : clé invalide. Elle doit être en base64, 32 octets.", 400

    try:
        padded_key = key + '=' * (-len(key) % 4)
        user_fernet = Fernet(padded_key.encode())
        decrypted = user_fernet.decrypt(token.encode()).decode()
        return f"Message déchiffré : {decrypted}"
    except Exception as e:
        return f"Erreur lors du déchiffrement : {str(e)}"

# ----------- Lancement local (facultatif) ----------- #
if __name__ == "__main__":
    app.run(debug=True)
