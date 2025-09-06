from flask import Flask, request, render_template
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
    if request.form.get('encrypt') == 'encrypt':
        return send_message()
    else:
        return decrypt()

def send_message():
    message = request.form.get('message')
    message = message.strip()
    message = message.encode()
    password = request.form.get('password')
    password = password.strip().encode()
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
def decrypt():
    try:
        ciphertext = request.form.get('message')
        ciphertext = ciphertext.strip()
        ciphertext = ciphertext.encode()
        password = request.form.get('password')
        password = password.strip()
        password = password.encode()

        ciphertext = bytes.fromhex(ciphertext.decode())  # Convert back to bytes
        encryption_key = encryption_key_gen(password)
        decipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend()) # Auch möglich mit modes.GMC()
        decryptor = decipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_text = decrypted_text.decode('utf-8')
        return render_template('ergebnis.html', message=decrypted_text)
    except UnicodeDecodeError:
        return render_template('ergebnis.html', message=ciphertext)
    

