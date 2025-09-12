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
    return render_template('index2.html')

@app.route('/sendMessage', methods=['POST'])
def sendMessage():
    message = request.form.get('message')
    password = request.form.get('password')
    fileCheck = request.form.get('fileCheck')
    file = False
    fileExtension = None
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            try:
                fileExtension = os.path.splitext(file.filename)[1]
                message = file.read()
                file = True
            except UnicodeDecodeError:
                return render_template('ergebnis.html', message="Fehler: Die Datei muss UTF-8 kodiert sein.")
    print(request.form.get('encrypt'))
    if request.form.get('encrypt') == 'encrypt': #TODO Fix function
        return send_message(message, password, file, fileExtension)
    else:
        if fileCheck == True:
            file = True
        return decrypt(message, password, file)

def encrypt(message, password, file=False):
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

def send_message(message, password, file=False, fileExtension=None):
    if not isinstance(message, bytes):
        message = message.encode()
    password = password.encode()
    if not message or not password:
        return render_template('ergebnis.html', message="Fehler: Nachricht und Passwort dürfen nicht leer sein.")
    # Pad the message to be a multiple of 16 bytes
    ciphertext = encrypt(message, password, file)
    fileExt = encrypt(fileExtension.encode(), password) if fileExtension else ''
    if file:
        ciphertext = fileExt + '|' + ciphertext
    if len(ciphertext) > 250:
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

def decrypt_message(ciphertext, password):
    try:
        encryption_key = encryption_key_gen(password)
        cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_text
    except Exception as e:
        return render_template('ergebnis.html', message="Fehler: " + str(e))

def decrypt(ciphertext, password, file=False):
    try:
        fileExtension = ciphertext.split(b'|', 1)[0] if file else None
        print(fileExtension)
        ciphertext = ciphertext.strip()
        if (file):
            ciphertext = ciphertext.split(b'|', 1)[1]
            ciphertext = bytes.fromhex(ciphertext.decode())  # Convert back to bytes
        else :
            ciphertext = bytes.fromhex(ciphertext)  # Convert back to bytes
        password = password.strip()
        password = password.encode()
        if not ciphertext or not password:
            return render_template('ergebnis.html', message="Fehler: Nachricht und Passwort dürfen nicht leer sein.")
        # ciphertext = bytes.fromhex(ciphertext.encode())  # Convert back to bytes
        decrypted_text = decrypt_message(ciphertext, password)
        

        if file:
            fileExt = decrypt_message(bytes.fromhex(fileExtension.decode()), password)
            fileExt = fileExt.decode()
            if '.' in fileExt:
                fileExtension = fileExt
            else:
                fileExtension = '.txt'
        # decrypted_text = base64.b64decode(decrypted_text)  # Decode from base64
        # print(decrypted_text)
        if not file:
            decrypted_text = decrypted_text.decode('utf-8').strip()
            if '\x0c' in decrypted_text:  # Use string version for decoded text
                decrypted_text = decrypted_text.replace('\x0c', '')
        else:
            if b'\x0b' in decrypted_text:  # Use bytes version for file data
                decrypted_text = decrypted_text.replace(b'\x0b', b'')
        if file:            
            # Create in-memory file
            mem_file = BytesIO()
            mem_file.write(decrypted_text)
            mem_file.seek(0)

            return send_file(
                mem_file,
                as_attachment=True,
                download_name='decrypted_message' + fileExtension,
                mimetype='text/' + fileExtension.lstrip('.')
            )
        return render_template('ergebnis.html', message=decrypted_text)
    except UnicodeDecodeError:
        return render_template('ergebnis.html', message="Fehler: Falscher Input oder Passwort")
    

