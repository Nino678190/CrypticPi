from flask import Flask, request, render_template
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

app = Flask(__name__)

def encryption_key_gen(password):
    salt = 'Das ist ein Salz'.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sendMessage', methods=['POST'])
def sendMessage():
    message = request.form.get('message')
    password = request.form.get('password')
    fileCheck = request.form.get('fileCheck')
    file = False
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            try:
                message = file.read()
                file = True
            except UnicodeDecodeError:
                return render_template('ergebnis.html', message="Fehler: Die Datei muss UTF-8 kodiert sein.")
    if request.form.get('encrypt') == 'encrypt':
        return send_message(message, password, file)
    else:
        if fileCheck == True:
            file = True
        return decrypt(message, password, file)

def send_message(message, password, file=False):
    message = message.strip()
    if not file:
        message = base64.b64encode(message.decode())
    password = password.strip().encode()
    if not message or not password:
        return render_template('ergebnis.html', message="Fehler: Nachricht und Passwort dürfen nicht leer sein.")
    # Pad the message to be a multiple of 16 bytes
    padding_length = 16 - (len(message) % 16)
    message = message + bytes([padding_length] * padding_length)
    encryption_key = encryption_key_gen(password)
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend()) # Auch möglich mit modes.GMC()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    ciphertext = ciphertext.hex() # Convert to string for easy transmission
    return render_template('ergebnis.html', message=ciphertext)


@app.route('/decrypt', methods=['POST'])
def decrypt(ciphertext, password, file=False):
    try:
        ciphertext = ciphertext.strip()
        ciphertext = ciphertext.encode()

        password = password.strip()
        password = password.encode()
        if not ciphertext or not password:
            return render_template('ergebnis.html', message="Fehler: Nachricht und Passwort dürfen nicht leer sein.")
        ciphertext = bytes.fromhex(ciphertext.decode())  # Convert back to bytes
        encryption_key = encryption_key_gen(password)
        decipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend()) # Auch möglich mit modes.GMC()
        decryptor = decipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_text = base64.b64decode(decrypted_text)  # Decode from base64
        if not file:
            decrypted_text = decrypted_text.decode('utf-8').strip()
        
        return render_template('ergebnis.html', message=decrypted_text)
    except UnicodeDecodeError:
        return render_template('ergebnis.html', message="Fehler: Falscher Input oder Passwort")
    

