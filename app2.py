from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt

app = Flask(__name__)
CORS(app)

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return 'Flask app is running!'

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Username and password required"}), 400

    username = data['username']
    password = data['password'].encode('utf-8')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if row:
        stored_hash = row[0]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')
        if bcrypt.checkpw(password, stored_hash):
            conn.close()
            return jsonify({"message": f"Welcome back, {username}!"}), 200
        else:
            conn.close()
            return jsonify({"message": "Invalid password!"}), 401
    else:
        try:
            hashed = bcrypt.hashpw(password, bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
            conn.commit()
            conn.close()
            return jsonify({"message": f"User {username} registered successfully."}), 201
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"message": "Username already exists!"}), 409

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
