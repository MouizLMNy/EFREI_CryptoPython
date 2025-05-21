from cryptography.fernet import Fernet
from flask import Flask, render_template_string, render_template, jsonify, request
from flask import render_template
from flask import json
from urllib.request import urlopen
import sqlite3

app = Flask(__name__)

@app.route('/')
def home():
    return "Bienvenue sur l'API de Cryptographie  avec clés personnalisées ! \n voici le url pour crypte un msg "
    
   #EXO 1
@app.route('/encrypt/<string:valeur>')
def encryptage(valeur):
    valeur_bytes = valeur.encode()  # Conversion str -> bytes
    token = f.encrypt(valeur_bytes)  # Encrypt la valeur
    return f"Valeur encryptée : {token.decode()}"  # Retourne le token en str

@app.route('/decrypt/<string:token>')
def decryptage(token):
    try:
        token_decoded = urllib.parse.unquote_plus(token)
        decrypted_bytes = f.decrypt(token_decoded.encode())
        decrypted = decrypted_bytes.decode()
        return f"Valeur décryptée : {decrypted}"
    except Exception as e:
        return f"Erreur lors du déchiffrement : {str(e)}"

#EXO 2

@app.route('/encrypt_custom')
def encrypt_custom():
    message = request.args.get('message')
    user_key = request.args.get('key')

    if not message or not user_key:
        return "Erreur : veuillez fournir un message ET une clé dans l'URL.", 400

    try:
        fernet = Fernet(user_key.encode())
        encrypted = fernet.encrypt(message.encode()).decode()
        return f"Message chiffré : {encrypted}"
    except Exception as e:
        return f"Erreur lors du chiffrement : {str(e)}"

@app.route('/decrypt_custom')
def decrypt_custom():
    token = request.args.get('token')
    user_key = request.args.get('key')

    if not token or not user_key:
        return "Erreur : veuillez fournir un token ET une clé dans l'URL.", 400

    try:
        fernet = Fernet(user_key.encode())
        decrypted = fernet.decrypt(token.encode()).decode()
        return f"Message déchiffré : {decrypted}"
    except Exception as e:
        return f"Erreur lors du déchiffrement : {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)

