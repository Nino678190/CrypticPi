from flask import Flask, request, render_template
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
from io import BytesIO
from flask import send_file

true = True
false = False

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

@app.route('/test')
def test():
    return render_template('index2.html')

@app.route('/sendMessage', methods=['POST'])
def sendMessage():
    message = request.form.get('message')
    password = request.form.get('password')
    print("Received message:", message, "with password:", password)
    if request.form.get('encrypt') == 'encrypt':
        return send_message(message, password)
    else:
        return decrypt(message, password)

def encrypt(message, password):
    try: 
        padding_length = 16 - (len(message) % 16)
        message = message + bytes([padding_length] * padding_length)
        encryption_key = encryption_key_gen(password)
        cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend()) # Auch möglich mit modes.GMC()
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        ciphertext = ciphertext.hex() # Convert to string for easy transmission
        return ciphertext
    except Exception as e:
        return render_template('ergebnis.html', message="Fehler: " + str(e))

# ...existing code...
def send_message(message, password):
    # Validate presence before attempting to encode
    if message is None or password is None:
        return render_template('ergebnis.html', message="Fehler: Nachricht und Passwort dürfen nicht leer sein.")
    # Convert str inputs to bytes, leave bytes as-is
    if isinstance(message, str):
        message = message.encode()
    if isinstance(password, str):
        password = password.encode()
    # Ensure non-empty bytes
    if not message or not password:
        return render_template('ergebnis.html', message="Fehler: Nachricht und Passwort dürfen nicht leer sein.")
    # Encrypt the message (encrypt expects bytes)
    ciphertext = encrypt(message, password)
    if isinstance(ciphertext, str) and len(ciphertext) > 250:
        # Create in-memory file
        mem_file = BytesIO()
        mem_file.write(ciphertext.encode())
        mem_file.seek(0)

        return send_file(
            mem_file,
            as_attachment=True,
            download_name='encrypted_message.txt',
            mimetype='text/plain'
        )
    return render_template('ergebnis.html', message=ciphertext)
# ...existing code...

def decrypt_message(ciphertext, password):
    try:
        encryption_key = encryption_key_gen(password)
        cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_text
    except Exception as e:
        return render_template('ergebnis.html', message="Fehler: " + str(e))

def decrypt(ciphertext, password):
    try:

        ciphertext = ciphertext.strip()

        ciphertext = bytes.fromhex(ciphertext)  # Convert back to bytes
        password = password.strip()
        password = password.encode()
        if not ciphertext or not password:
            return render_template('ergebnis.html', message="Fehler: Nachricht und Passwort dürfen nicht leer sein.")
        # ciphertext = bytes.fromhex(ciphertext.encode())  # Convert back to bytes
        decrypted_text = decrypt_message(ciphertext, password)

        decrypted_text = decrypted_text.decode('utf-8').strip()
        if '\x0c' in decrypted_text:  # Use string version for decoded text
            decrypted_text = decrypted_text.replace('\x0c', '')
        return render_template('ergebnis.html', message=decrypted_text)
    except UnicodeDecodeError:
        return render_template('ergebnis.html', message="Fehler: Falscher Input oder Passwort")
    

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)

