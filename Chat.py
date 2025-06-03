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
            return "Invalid username or password."
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
            return "Username already exists. Please choose another one."
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
            chat_data = cursor.fetchone() # Renamed to avoid conflict with function name
            if chat_data:
                if chat_data[2] is None or chat_data[2] == user_id or chat_data[1] == user_id : # Allow if user2 is null or current user is user1 or user2
                    if chat_data[2] is None and chat_data[1] != user_id: # If user2 is null and current user is not user1, set user2
                        cursor.execute('UPDATE chats SET user2_id = ? WHERE encryption_key = ?', (user_id, encryption_key))
                        conn.commit()
                    chat_id = chat_data[0]
                    conn.close()
                    return redirect(url_for('chat_room', chat_id=chat_id))
                else: # user2 is set and is not the current user, and current user is not user1
                    conn.close()
                    return "Chat is already full or you are not part of this chat."
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
    chat_data = cursor.fetchone() # Renamed
    if not chat_data or user_id not in (chat_data[0], chat_data[1]): # Check if user is part of the chat
        conn.close()
        return jsonify(messages=[]) # Return empty if not part of chat
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
            print(f"Error decrypting message: {e}") # Log error
            # Optionally, send a placeholder for undecryptable messages
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
    chat_data = cursor.fetchone() # Renamed
    if not chat_data or user_id not in (chat_data[0], chat_data[1]): # Check if user is part of the chat
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
    chat_data = cursor.fetchone() # Renamed
    if not chat_data or user_id not in (chat_data[0], chat_data[1]): # Check if user is part of the chat
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

    user_id = session['user_id'] # Get current user's ID
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Verify that the current user is part of the chat they are trying to delete
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
    if 'username' not in session: # Basic auth check
        return jsonify(success=False, error="Unauthorized"), 401

    # More robust: ensure only an admin or based on specific logic can do this
    # For now, any logged-in user can delete all chats, which is DANGEROUS.
    # This should be restricted in a real application.

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM messages')
        cursor.execute('DELETE FROM chats')
        # If using foreign key constraints with ON DELETE CASCADE, messages might be deleted automatically
        # Re-check if users should be deleted or if this is just about chat content
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
    chat_data = cursor.fetchone() # Renamed

    if not chat_data:
        conn.close()
        return "Chat not found.", 404

    # Ensure the current user is part of this chat
    if user_id not in (chat_data[2], chat_data[3]):
        conn.close()
        # Instead of just "Chat not found", give a more specific message or redirect
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
    user_id = session.get('user_id') # Use session.get to avoid KeyError if user_id is not in session
    if not user_id:
        emit('status', {'msg': 'Authentication error: User not logged in.'}, room=request.sid) # Emit to specific client
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id FROM chats WHERE chat_id = ?', (chat_id,))
    chat_data = cursor.fetchone() # Renamed
    conn.close()
    # Ensure user is part of the chat before joining the room
    if chat_data and user_id in (chat_data[0], chat_data[1]):
        join_room(str(chat_id))
        emit('status', {'msg': session.get('username', 'A user') + ' has joined the room.'}, room=str(chat_id)) # More informative
    else:
        # Optionally emit an error/status message back to the user
        emit('status', {'msg': 'Error joining room or not authorized.'}, room=request.sid)


@socketio.on('send_message')
def handle_socket_message(data):
    chat_id = data.get('chat_id')
    message = data.get('message')
    user_id = session.get('user_id') # Use session.get
    if not user_id:
        # Handle case where user is not logged in or session expired
        emit('status', {'msg': 'Authentication error. Cannot send message.'}, room=request.sid)
        return

    if not message or len(message.strip()) == 0: # Prevent empty messages
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT user1_id, user2_id, encryption_key FROM chats WHERE chat_id = ?', (chat_id,))
    chat_data = cursor.fetchone() # Renamed

    if not chat_data or user_id not in (chat_data[0], chat_data[1]): # Ensure user is part of chat
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

    sender_name = session.get('username', 'Unknown User') # Get username from session
    conn.close() # Close connection after DB operations

    # Emit to all users in the room, including sender for confirmation
    emit('receive_message', {'sender': sender_name, 'message': message, 'timestamp': timestamp, 'chat_id': chat_id}, room=str(chat_id))


# Route to logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    # Consider security implications of debug=True in anything resembling a production environment
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
