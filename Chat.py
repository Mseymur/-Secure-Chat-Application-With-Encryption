import sqlite3
import random
import string
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'
socketio = SocketIO(app, cors_allowed_origins="*")

# Database configuration
DB_NAME = 'users.db'

# Function to initialize the database and update schema
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Create users table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    ''')
    # Create chats table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chats (
        chat_id INTEGER PRIMARY KEY AUTOINCREMENT,
        encryption_key TEXT NOT NULL UNIQUE,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER,
        FOREIGN KEY (user1_id) REFERENCES users (id),
        FOREIGN KEY (user2_id) REFERENCES users (id)
    )
    ''')
    # Add chat_name column if it doesn't exist
    cursor.execute('''
    PRAGMA table_info(chats);
    ''')
    columns = [col[1] for col in cursor.fetchall()]
    if 'chat_name' not in columns:
        cursor.execute('''
        ALTER TABLE chats ADD COLUMN chat_name TEXT;
        ''')
    # Create messages table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        message_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (chat_id) REFERENCES chats (chat_id),
        FOREIGN KEY (sender_id) REFERENCES users (id)
    )
    ''')
    # Ensure timestamp column exists
    cursor.execute('PRAGMA table_info(messages);')
    msg_columns = [col[1] for col in cursor.fetchall()]
    if 'timestamp' not in msg_columns:
        cursor.execute('ALTER TABLE messages ADD COLUMN timestamp TEXT;')
    conn.commit()
    conn.close()


# Route for the home page
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('chat'))
    return render_template('home.html')

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['username'] = username
            session['user_id'] = user[0]
            flash('Logged in successfully.', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

# Route for sign up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        try:
            hashed_password = generate_password_hash(password)
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username already exists. Please choose another one.', 'error')
            return redirect(url_for('signup'))
    return render_template('signup.html')

# Route for password reset
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user:
            hashed_password = generate_password_hash(new_password)
            cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
            conn.commit()
            conn.close()
            flash('Password updated. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            conn.close()
            flash('Username not found.', 'error')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

# Route for chat
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        action = request.form['action']
        if action == 'create':
            encryption_key = Fernet.generate_key().decode()
            chat_name = request.form['chat_name']
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO chats (encryption_key, chat_name, user1_id) VALUES (?, ?, ?)', (encryption_key, chat_name, user_id))
            conn.commit()
            chat_id = cursor.lastrowid
            conn.close()
            return redirect(url_for('chat_room', chat_id=chat_id))
        elif action == 'join':
            encryption_key = request.form['encryption_key']
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('SELECT chat_id, user1_id, user2_id FROM chats WHERE encryption_key = ?', (encryption_key,))
            chat = cursor.fetchone()
            if chat:
                if chat[2] is None:
                    cursor.execute('UPDATE chats SET user2_id = ? WHERE encryption_key = ?', (user_id, encryption_key))
                    conn.commit()
                    chat_id = chat[0]
                    conn.close()
                    return redirect(url_for('chat_room', chat_id=chat_id))
                else:
                    conn.close()
                    return "Chat is already full."
            else:
                conn.close()
                return "Invalid encryption key."
    
    return render_template('chat.html')

# Route to get chat messages
@app.route('/get_messages/<int:chat_id>', methods=['GET'])
def get_messages(chat_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id, encryption_key FROM chats WHERE chat_id = ?', (chat_id,))
    chat = cursor.fetchone()
    if not chat or user_id not in chat[:2]:
        conn.close()
        return jsonify(messages=[])
    encryption_key = chat[2]
    cursor.execute('''
        SELECT messages.message, messages.timestamp, users.username
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE messages.chat_id = ?
        ORDER BY messages.message_id ASC
    ''', (chat_id,))
    messages = cursor.fetchall()
    conn.close()

    decrypted_messages = []
    cipher = Fernet(encryption_key.encode())
    for msg in messages:
        decrypted_message = cipher.decrypt(base64.b64decode(msg[0])).decode()
        decrypted_messages.append({'sender': msg[2], 'message': decrypted_message, 'timestamp': msg[1]})

    return jsonify(messages=decrypted_messages)

# Route to send chat messages
@app.route('/send_message/<int:chat_id>', methods=['POST'])
def send_message(chat_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    data = request.get_json()
    message = data['message']
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id, encryption_key FROM chats WHERE chat_id = ?', (chat_id,))
    chat = cursor.fetchone()
    if not chat or user_id not in chat[:2]:
        conn.close()
        return jsonify(success=False)
    encryption_key = chat[2]

    cipher = Fernet(encryption_key.encode())
    encrypted_message = base64.b64encode(cipher.encrypt(message.encode())).decode()
    timestamp = datetime.utcnow().isoformat()
    cursor.execute('INSERT INTO messages (chat_id, sender_id, message, timestamp) VALUES (?, ?, ?, ?)',
                   (chat_id, user_id, encrypted_message, timestamp))
    conn.commit()
    conn.close()

    return jsonify(success=True)

# Route to edit chat name
@app.route('/edit_chat_name/<int:chat_id>', methods=['POST'])
def edit_chat_name(chat_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    new_name = request.get_json().get('new_chat_name')
    user_id = session['user_id']

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id FROM chats WHERE chat_id = ?', (chat_id,))
    chat = cursor.fetchone()
    if not chat or user_id not in chat:
        conn.close()
        return jsonify(success=False)
    cursor.execute('UPDATE chats SET chat_name = ? WHERE chat_id = ?', (new_name, chat_id))
    conn.commit()
    conn.close()
    return jsonify(success=True)

# Route to delete chat
@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
def delete_chat(chat_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM messages WHERE chat_id = ?', (chat_id,))
    cursor.execute('DELETE FROM chats WHERE chat_id = ?', (chat_id,))
    conn.commit()
    conn.close()
    
    return jsonify(success=True)

# Route to delete all chats
@app.route('/delete_all_chats', methods=['POST'])
def delete_all_chats():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM messages')
    cursor.execute('DELETE FROM chats')
    conn.commit()
    conn.close()
    
    return jsonify(success=True)

# Route to display chat room
@app.route('/chat_room/<int:chat_id>')
def chat_room(chat_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT chat_name, encryption_key FROM chats WHERE chat_id = ?', (chat_id,))
    chat = cursor.fetchone()
    chat_name, encryption_key = chat
    conn.close()
    
    return render_template('chat_room.html', chat_id=chat_id, username=session['username'], chat_name=chat_name, encryption_key=encryption_key)

# Route to get joined chats
@app.route('/get_chats', methods=['GET'])
def get_chats():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT chat_id, encryption_key, chat_name FROM chats WHERE user1_id = ? OR user2_id = ?', (user_id, user_id))
    chats = cursor.fetchall()
    conn.close()
    
    return jsonify(chats=[{'chat_id': chat[0], 'encryption_key': chat[1], 'chat_name': chat[2]} for chat in chats])

# Socket.IO events
@socketio.on('join')
def handle_join(data):
    chat_id = data.get('chat_id')
    user_id = session.get('user_id')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id FROM chats WHERE chat_id = ?', (chat_id,))
    chat = cursor.fetchone()
    conn.close()
    if chat and user_id in chat:
        join_room(str(chat_id))
        emit('status', {'msg': 'Joined room'}, room=str(chat_id))

@socketio.on('send_message')
def handle_socket_message(data):
    chat_id = data.get('chat_id')
    message = data.get('message')
    user_id = session.get('user_id')
    if not message:
        return
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id, encryption_key FROM chats WHERE chat_id = ?', (chat_id,))
    chat = cursor.fetchone()
    if not chat or user_id not in chat[:2]:
        conn.close()
        return
    encryption_key = chat[2]
    cipher = Fernet(encryption_key.encode())
    encrypted_message = base64.b64encode(cipher.encrypt(message.encode())).decode()
    timestamp = datetime.utcnow().isoformat()
    cursor.execute('INSERT INTO messages (chat_id, sender_id, message, timestamp) VALUES (?, ?, ?, ?)',
                   (chat_id, user_id, encrypted_message, timestamp))
    conn.commit()
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    sender_name = cursor.fetchone()[0]
    conn.close()
    emit('receive_message', {'sender': sender_name, 'message': message, 'timestamp': timestamp}, room=str(chat_id))

# Route to logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
