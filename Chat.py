import sqlite3
import random
import string
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# IMPORTANT: This is a placeholder secret key and is INSECURE.
# For production, use a strong, randomly generated key and consider loading it
# from an environment variable or a secure configuration file.
# Example: import os; app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_if_not_set_but_should_be_random')
app.secret_key = 'supersecretkey'

# NOTE: For production deployment, always serve this application over HTTPS
# to protect user credentials and message content during transit.
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
        encryption_key TEXT NOT NULL UNIQUE, -- IMPORTANT: Encryption keys are stored here. DB security is crucial.
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
            return redirect(url_for('chat'))
        else:
            # return "Invalid username or password."
            return render_template('login.html', error="Invalid username or password.")
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
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            # return "Username already exists. Please choose another one."
            return render_template('signup.html', error="Username already exists. Please choose another one.")
    return render_template('signup.html')

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
            chat_name = request.form.get('chat_name', 'New Chat') # Default chat name if not provided
            if not chat_name.strip(): # Ensure chat name is not just whitespace
                chat_name = "New Chat"
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
            chat_data = cursor.fetchone()
            if chat_data:
                chat_id_val, user1_id_val, user2_id_val = chat_data
                # Allow if user is already part of the chat or if there's space
                if user_id == user1_id_val or user_id == user2_id_val:
                    conn.close()
                    return redirect(url_for('chat_room', chat_id=chat_id_val))
                elif user2_id_val is None: # If user2 is null and current user is not user1 (already checked), set user2
                    cursor.execute('UPDATE chats SET user2_id = ? WHERE encryption_key = ?', (user_id, encryption_key))
                    conn.commit()
                    conn.close()
                    return redirect(url_for('chat_room', chat_id=chat_id_val))
                else:
                    conn.close()
                    return render_template('chat.html', join_error="Chat is already full.", encryption_key_value=encryption_key, show_join_form=True)
            else:
                conn.close()
                return render_template('chat.html', join_error="Invalid encryption key.", encryption_key_value=encryption_key, show_join_form=True)

    # For GET request, or if POST is not 'create' or 'join' (though current logic doesn't lead here)
    return render_template('chat.html', join_error=None, encryption_key_value=None, show_join_form=False)


# Route to get chat messages
@app.route('/get_messages/<int:chat_id>', methods=['GET'])
def get_messages(chat_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id, encryption_key FROM chats WHERE chat_id = ?', (chat_id,))
    chat_data = cursor.fetchone()
    if not chat_data or user_id not in (chat_data[0], chat_data[1]):
        conn.close()
        return jsonify(messages=[])
    encryption_key = chat_data[2]
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
        try:
            decrypted_message = cipher.decrypt(base64.b64decode(msg[0])).decode()
            decrypted_messages.append({'sender': msg[2], 'message': decrypted_message, 'timestamp': msg[1]})
        except Exception as e:
            print(f"Error decrypting message: {e}")
            decrypted_messages.append({'sender': msg[2], 'message': '[Undecryptable Message]', 'timestamp': msg[1]})


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
    chat_data = cursor.fetchone()
    if not chat_data or user_id not in (chat_data[0], chat_data[1]):
        conn.close()
        return jsonify(success=False, error="User not part of chat")
    encryption_key = chat_data[2]

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
    if not new_name or len(new_name.strip()) == 0:
        return jsonify(success=False, error="Chat name cannot be empty.")

    user_id = session['user_id']

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id FROM chats WHERE chat_id = ?', (chat_id,))
    chat_data = cursor.fetchone()
    if not chat_data or user_id not in (chat_data[0], chat_data[1]):
        conn.close()
        return jsonify(success=False, error="User not part of chat")
    cursor.execute('UPDATE chats SET chat_name = ? WHERE chat_id = ?', (new_name, chat_id))
    conn.commit()
    conn.close()
    return jsonify(success=True)

# Route to delete chat
@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
def delete_chat(chat_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id FROM chats WHERE chat_id = ?', (chat_id,))
    chat_data = cursor.fetchone()
    if not chat_data or user_id not in (chat_data[0], chat_data[1]):
        conn.close()
        return jsonify(success=False, error="User not authorized to delete this chat or chat does not exist.")

    cursor.execute('DELETE FROM messages WHERE chat_id = ?', (chat_id,))
    cursor.execute('DELETE FROM chats WHERE chat_id = ?', (chat_id,))
    conn.commit()
    conn.close()

    return jsonify(success=True)

# Route to delete all chats
@app.route('/delete_all_chats', methods=['POST'])
def delete_all_chats():
    if 'username' not in session:
        return jsonify(success=False, error="Unauthorized"), 401

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM messages')
        cursor.execute('DELETE FROM chats')
        conn.commit()
        success = True
        message = "All chats and messages have been deleted."
    except Exception as e:
        conn.rollback()
        print(f"Error deleting all chats: {e}")
        success = False
        message = "An error occurred while deleting all chats."
    finally:
        conn.close()

    return jsonify(success=success, message=message)


# Route to display chat room
@app.route('/chat_room/<int:chat_id>')
def chat_room(chat_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT chat_name, encryption_key, user1_id, user2_id FROM chats WHERE chat_id = ?', (chat_id,))
    chat_data = cursor.fetchone()

    if not chat_data:
        conn.close()
        return "Chat not found.", 404

    if user_id not in (chat_data[2], chat_data[3]):
        conn.close()
        return "You are not a participant in this chat.", 403


    chat_name, encryption_key = chat_data[0], chat_data[1]
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
    if not user_id:
        emit('status', {'msg': 'Authentication error: User not logged in.'}, room=request.sid)
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id FROM chats WHERE chat_id = ?', (chat_id,))
    chat_data = cursor.fetchone()
    conn.close()
    if chat_data and user_id in (chat_data[0], chat_data[1]):
        join_room(str(chat_id))
        emit('status', {'msg': session.get('username', 'A user') + ' has joined the room.'}, room=str(chat_id))
    else:
        emit('status', {'msg': 'Error joining room or not authorized.'}, room=request.sid)


@socketio.on('send_message')
def handle_socket_message(data):
    chat_id = data.get('chat_id')
    message = data.get('message')
    user_id = session.get('user_id')
    if not user_id:
        emit('status', {'msg': 'Authentication error. Cannot send message.'}, room=request.sid)
        return

    if not message or len(message.strip()) == 0:
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id, encryption_key FROM chats WHERE chat_id = ?', (chat_id,))
    chat_data = cursor.fetchone()

    if not chat_data or user_id not in (chat_data[0], chat_data[1]):
        conn.close()
        emit('status', {'msg': 'Cannot send message: Not part of this chat or chat does not exist.'}, room=request.sid)
        return

    encryption_key = chat_data[2]
    cipher = Fernet(encryption_key.encode())
    try:
        encrypted_message = base64.b64encode(cipher.encrypt(message.encode())).decode()
    except Exception as e:
        print(f"Error encrypting message: {e}")
        emit('status', {'msg': 'Error processing message. Could not encrypt.'}, room=request.sid)
        conn.close()
        return

    timestamp = datetime.utcnow().isoformat()
    try:
        cursor.execute('INSERT INTO messages (chat_id, sender_id, message, timestamp) VALUES (?, ?, ?, ?)',
                       (chat_id, user_id, encrypted_message, timestamp))
        conn.commit()
    except Exception as e:
        print(f"Error saving message to DB: {e}")
        conn.rollback()
        emit('status', {'msg': 'Error saving message to database.'}, room=request.sid)
        conn.close()
        return

    sender_name = session.get('username', 'Unknown User')
    conn.close()

    emit('receive_message', {'sender': sender_name, 'message': message, 'timestamp': timestamp, 'chat_id': chat_id}, room=str(chat_id))


# Route to logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
