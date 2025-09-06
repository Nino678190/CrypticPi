from flask import Flask, request, jsonify
import os
import serial
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello, World!"

@app.route('/getKey', methods=['GET'])
def get_key():
    password = b"my_encryption_password"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return jsonify({"key": kdf.derive(password).hex(), "salt": salt.hex()})
    encryption_key = kdf.derive(password)

@app.route('/sendMessage', methods=['POST'])
def send_message():
    data = request.json
    message = data.get('message', '')
    password = data.get('password', '')
    passwordCheck = hash_password(password)
    if not bcrypt.checkpw(password.encode(), passwordCheck):
        return jsonify({"error": "Unauthorized"}), 401

    ser = serial.Serial('/dev/ttyUSB0', timeout=1)
    ser.write(message.encode())
    ser.close()
    print('Message: ', message)
    return "<p>Das ist die Nachricht: {}</p>".format(message)




# Generate a key using KDF


# Encryption
plaintext = b"Hello, World!"
cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Decryption
decipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
decryptor = decipher.decryptor()
decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

print(f"Plaintext: {plaintext}")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Decrypted text: {decrypted_text}")