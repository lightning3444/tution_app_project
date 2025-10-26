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

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # WARNING: Logging password; NEVER do this in production
    print(f"Login attempt with username: {username} and password: {password}")

    password_bytes = password.encode('utf-8')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()

    if row:
        stored_hash = row[0]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')

        if bcrypt.checkpw(password_bytes, stored_hash):
            conn.close()
            return jsonify({"message": f"Welcome back, {username}!"}), 200
        else:
            conn.close()
            return jsonify({"message": "Invalid password!"}), 401
    else:
        hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
            conn.commit()
            conn.close()
            return jsonify({"message": f"New user {username} registered successfully!"}), 201
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"message": "Failed to register user!"}), 400

if __name__ == "__main__":
    app.run(debug=True)
