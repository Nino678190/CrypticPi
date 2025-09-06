from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello, World!"

@app.route('/sendMessage', methods=['POST'])
def send_message():
    message = request.form.get('message')
    print('Message: ', message)
    return "<p>Das ist die Nachricht: {}</p>".format(message)