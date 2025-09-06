from flask import Flask, request
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

app = Flask(__name__)

def load_config():
    with open("config.json", "r") as f:
        config = json.load(f)

    return config


config = load_config()
password = config['encryption_password']


salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
encryption_key = kdf.derive(password)


@app.route('/')
def index():
    return "Hello, World!"

@app.route('/sendMessage', methods=['POST'])
def send_message():
    message = request.form.get('message')
    print('Message: ', message)
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return "<p>Das ist die verschlüsselte Nachricht: {}</p>".format(ciphertext)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form.get('ciphertext')
    decipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
    decryptor = decipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    return "<p>Das ist die entschlüsselte Nachricht: {}</p>".format(decrypted_text)

