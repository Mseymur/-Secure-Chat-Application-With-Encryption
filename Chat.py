import sqlite3
import random
import string
import base64
import io
import pyotp
import qrcode
import os
import logging
from datetime import datetime
from cryptography.fernet import Fernet
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, send_file
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from error_handlers import register_error_handlers

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Initialize Flask app
app = Flask(__name__)

# Set secret key from environment variable or use a default for development
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')

# Configure SocketIO with CORS settings
socketio = SocketIO(app, cors_allowed_origins="*")

# Register error handlers
register_error_handlers(app)

# Database configuration
DB_NAME = os.environ.get('DB_NAME', 'users.db')

# Initialize database and create tables if they don't exist
def init_db():
    try:
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
        
        # Add totp_secret column if it doesn't exist
        cursor.execute('''
        PRAGMA table_info(users);
        ''')
        columns = [col[1] for col in cursor.fetchall()]
        if 'totp_secret' not in columns:
            cursor.execute('''
            ALTER TABLE users ADD COLUMN totp_secret TEXT;
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
        app.logger.info("Database initialized successfully")
        return True
    except Exception as e:
        app.logger.error(f"Database initialization error: {e}")
        return False

# Initialize the database when the module is imported
init_db()

# Add template filter for current year
@app.template_filter('now')
def filter_now(format_string):
    if format_string == 'year':
        return datetime.now().year
    return datetime.now().strftime(format_string)

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
        totp_code = request.form['totp_code']

        if not username or not password or not totp_code:
            return render_template('error.html', 
                title="Login Error",
                heading="Login Failed",
                message="Username, password, and authentication code are required.",
                icon="fa-user-lock",
                color="warning",
                back_url=url_for('login'),
                back_text="Back to Login"
            )

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT id, password, totp_secret FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password) and user[2]:
            # Verify TOTP code
            totp = pyotp.TOTP(user[2])
            if totp.verify(totp_code):
                session['username'] = username
                session['user_id'] = user[0]
                return redirect(url_for('chat'))
        
        return render_template('error.html', 
            title="Login Failed",
            heading="Invalid Credentials",
            message="The username, password, or authentication code you entered is incorrect.",
            icon="fa-user-lock",
            color="danger",
            back_url=url_for('login'),
            back_text="Try Again"
        )
    return render_template('login.html')

# Route for sign up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm-password', '')
        
        # Validate inputs
        if not username or not password:
            return render_template('error.html', 
                title="Signup Error",
                heading="Signup Failed",
                message="Username and password are required.",
                icon="fa-user-plus",
                color="warning",
                back_url=url_for('signup'),
                back_text="Back to Signup"
            )
            
        if password != confirm_password:
            return render_template('error.html', 
                title="Signup Error",
                heading="Passwords Don't Match",
                message="The passwords you entered do not match.",
                icon="fa-user-plus",
                color="warning",
                back_url=url_for('signup'),
                back_text="Back to Signup"
            )
            
        if len(username) < 3:
            return render_template('error.html', 
                title="Signup Error",
                heading="Invalid Username",
                message="Username must be at least 3 characters long.",
                icon="fa-user-plus",
                color="warning",
                back_url=url_for('signup'),
                back_text="Back to Signup"
            )
            
        if len(password) < 8:
            return render_template('error.html', 
                title="Signup Error",
                heading="Weak Password",
                message="Password must be at least 8 characters long.",
                icon="fa-user-plus",
                color="warning",
                back_url=url_for('signup'),
                back_text="Back to Signup"
            )

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        try:
            # Generate a random TOTP secret for 2FA
            totp_secret = pyotp.random_base32()
            
            # Hash the password
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            
            cursor.execute('INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)', 
                          (username, hashed_password, totp_secret))
            conn.commit()
            
            # Get the user ID for the session
            user_id = cursor.lastrowid
            conn.close()
            
            # Set session variables
            session['username'] = username
            session['user_id'] = user_id
            session['totp_secret'] = totp_secret
            
            # Redirect to 2FA setup page
            return redirect(url_for('setup_2fa'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('error.html', 
                title="Signup Error",
                heading="Username Already Exists",
                message="This username is already taken. Please choose another one.",
                icon="fa-user-plus",
                color="warning",
                back_url=url_for('signup'),
                back_text="Back to Signup"
            )
    return render_template('signup.html')

# Welcome page for new users
@app.route('/welcome')
def welcome():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    return render_template('welcome.html', username=session['username'])

# Route for chat
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        action = request.form['action']
        if action == 'create':
            chat_name = request.form.get('chat_name', '').strip()
            
            if not chat_name:
                return render_template('error.html', 
                    title="Chat Creation Error",
                    heading="Invalid Chat Name",
                    message="Please provide a name for your chat.",
                    icon="fa-comments",
                    color="warning",
                    back_url=url_for('chat'),
                    back_text="Back to Chats"
                )
                
            encryption_key = Fernet.generate_key().decode()
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            try:
                cursor.execute('INSERT INTO chats (encryption_key, chat_name, user1_id) VALUES (?, ?, ?)', 
                            (encryption_key, chat_name, user_id))
                conn.commit()
                chat_id = cursor.lastrowid
                conn.close()
                return redirect(url_for('chat_room', chat_id=chat_id))
            except Exception as e:
                conn.close()
                return render_template('error.html', 
                    title="Chat Creation Error",
                    heading="Failed to Create Chat",
                    message="An error occurred while creating the chat.",
                    details=str(e) if app.debug else None,
                    icon="fa-comments",
                    color="danger",
                    back_url=url_for('chat'),
                    back_text="Back to Chats"
                )
                
        elif action == 'join':
            encryption_key = request.form.get('encryption_key', '').strip()
            
            if not encryption_key:
                return render_template('error.html', 
                    title="Join Chat Error",
                    heading="Missing Encryption Key",
                    message="Please provide an encryption key to join a chat.",
                    icon="fa-key",
                    color="warning",
                    back_url=url_for('chat'),
                    back_text="Back to Chats"
                )
                
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('SELECT chat_id, user1_id, user2_id FROM chats WHERE encryption_key = ?', (encryption_key,))
            chat_data = cursor.fetchone()
            
            if chat_data:
                if chat_data[2] is None and chat_data[1] != user_id:
                    # If user2 is null and current user is not user1, set user2
                    cursor.execute('UPDATE chats SET user2_id = ? WHERE encryption_key = ?', (user_id, encryption_key))
                    conn.commit()
                    chat_id = chat_data[0]
                    conn.close()
                    return redirect(url_for('chat_room', chat_id=chat_id))
                elif chat_data[1] == user_id or chat_data[2] == user_id:
                    # User is already part of this chat
                    chat_id = chat_data[0]
                    conn.close()
                    return redirect(url_for('chat_room', chat_id=chat_id))
                else:
                    # Chat is full with other users
                    conn.close()
                    return render_template('error.html', 
                        title="Join Chat Error",
                        heading="Chat is Full",
                        message="This chat already has two participants and cannot accept more users.",
                        icon="fa-users-slash",
                        color="warning",
                        back_url=url_for('chat'),
                        back_text="Back to Chats"
                    )
            else:
                conn.close()
                return render_template('error.html', 
                    title="Join Chat Error",
                    heading="Invalid Encryption Key",
                    message="The encryption key you entered does not match any existing chat.",
                    icon="fa-key",
                    color="danger",
                    back_url=url_for('chat'),
                    back_text="Back to Chats"
                )

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
    username = session['username']

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT chat_name, encryption_key, user1_id, user2_id FROM chats WHERE chat_id = ?', (chat_id,))
    chat_data = cursor.fetchone()
    conn.close()

    if not chat_data:
        return render_template('error.html', 
            title="Chat Not Found",
            heading="Chat Not Found",
            message="The chat you're looking for doesn't exist or has been deleted.",
            icon="fa-search",
            color="warning",
            back_url=url_for('chat'),
            back_text="Back to Chats"
        )

    # Check if user is part of this chat
    if user_id != chat_data[2] and user_id != chat_data[3]:
        return render_template('error.html', 
            title="Access Denied",
            heading="Unauthorized Access",
            message="You don't have permission to access this chat.",
            icon="fa-lock",
            color="danger",
            back_url=url_for('chat'),
            back_text="Back to Chats"
        )

    chat_name = chat_data[0] or f"Chat {chat_id}"
    encryption_key = chat_data[1]

    return render_template('chat_room.html', chat_id=chat_id, chat_name=chat_name, encryption_key=encryption_key, username=username)

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

# User profile page
@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    username = session['username']
    
    # Get user info and stats
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Get user join date (for demo purposes, we'll use current date if not available)
    cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    joined_date = datetime.now().strftime('%B %d, %Y')
    
    # Get chat count
    cursor.execute('''
        SELECT COUNT(*) FROM chats 
        WHERE user1_id = ? OR user2_id = ?
    ''', (user_id, user_id))
    chat_count = cursor.fetchone()[0]
    
    # Get message count
    cursor.execute('''
        SELECT COUNT(*) FROM messages 
        WHERE sender_id = ?
    ''', (user_id,))
    message_count = cursor.fetchone()[0]
    
    # Get contact count (unique users chatted with)
    cursor.execute('''
        SELECT COUNT(DISTINCT 
            CASE 
                WHEN user1_id = ? THEN user2_id 
                WHEN user2_id = ? THEN user1_id 
            END) 
        FROM chats 
        WHERE (user1_id = ? OR user2_id = ?) 
        AND user1_id IS NOT NULL 
        AND user2_id IS NOT NULL
    ''', (user_id, user_id, user_id, user_id))
    contact_count = cursor.fetchone()[0]
    
    conn.close()
    
    stats = {
        'chats': chat_count,
        'messages': message_count,
        'contacts': contact_count
    }
    
    return render_template('profile.html', username=username, joined_date=joined_date, stats=stats)

# Change password route
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate inputs
    if not current_password or not new_password or not confirm_password:
        return render_template('error.html', 
            title="Password Change Error",
            heading="Missing Information",
            message="All password fields are required.",
            icon="fa-key",
            color="warning",
            back_url=url_for('profile'),
            back_text="Back to Profile"
        )
    
    if new_password != confirm_password:
        return render_template('error.html', 
            title="Password Change Error",
            heading="Passwords Don't Match",
            message="The new passwords you entered do not match.",
            icon="fa-key",
            color="warning",
            back_url=url_for('profile'),
            back_text="Back to Profile"
        )
    
    if len(new_password) < 8:
        return render_template('error.html', 
            title="Password Change Error",
            heading="Weak Password",
            message="New password must be at least 8 characters long.",
            icon="fa-key",
            color="warning",
            back_url=url_for('profile'),
            back_text="Back to Profile"
        )
    
    # Verify current password and update
    user_id = session['user_id']
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
    stored_password = cursor.fetchone()[0]
    
    if not check_password_hash(stored_password, current_password):
        conn.close()
        return render_template('error.html', 
            title="Password Change Error",
            heading="Incorrect Password",
            message="The current password you entered is incorrect.",
            icon="fa-key",
            color="danger",
            back_url=url_for('profile'),
            back_text="Back to Profile"
        )
    
    # Update password
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
    conn.commit()
    conn.close()
    
    return render_template('error.html', 
        title="Password Changed",
        heading="Password Updated Successfully",
        message="Your password has been changed. Please use your new password the next time you log in.",
        icon="fa-check-circle",
        color="success",
        back_url=url_for('profile'),
        back_text="Back to Profile"
    )

# Delete account route
@app.route('/delete_account')
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # Begin transaction
        conn.execute('BEGIN TRANSACTION')
        
        # Delete messages sent by the user
        cursor.execute('DELETE FROM messages WHERE sender_id = ?', (user_id,))
        
        # Get chats where user is user1 or user2
        cursor.execute('''
            SELECT chat_id, user1_id, user2_id FROM chats 
            WHERE user1_id = ? OR user2_id = ?
        ''', (user_id, user_id))
        chats = cursor.fetchall()
        
        # Process each chat
        for chat in chats:
            chat_id, user1, user2 = chat
            
            # If user is the only participant, delete the chat
            if (user1 == user_id and user2 is None) or (user1 is None and user2 == user_id):
                # Delete all messages in the chat
                cursor.execute('DELETE FROM messages WHERE chat_id = ?', (chat_id,))
                # Delete the chat
                cursor.execute('DELETE FROM chats WHERE chat_id = ?', (chat_id,))
            # If user is user1, and user2 exists, make user2 the owner
            elif user1 == user_id and user2 is not None:
                cursor.execute('UPDATE chats SET user1_id = ?, user2_id = NULL WHERE chat_id = ?', (user2, chat_id))
            # If user is user2, just remove them
            elif user2 == user_id:
                cursor.execute('UPDATE chats SET user2_id = NULL WHERE chat_id = ?', (chat_id,))
        
        # Delete the user
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        
        # Commit transaction
        conn.commit()
        
        # Clear session
        session.clear()
        
        return render_template('error.html', 
            title="Account Deleted",
            heading="Account Successfully Deleted",
            message="Your account and all associated data have been permanently deleted.",
            icon="fa-check-circle",
            color="success",
            back_url=url_for('home'),
            back_text="Return to Home"
        )
    except Exception as e:
        # Rollback on error
        conn.rollback()
        conn.close()
        
        return render_template('error.html', 
            title="Account Deletion Error",
            heading="Failed to Delete Account",
            message="An error occurred while deleting your account. Please try again later.",
            details=str(e) if app.debug else None,
            icon="fa-exclamation-triangle",
            color="danger",
            back_url=url_for('profile'),
            back_text="Back to Profile"
        )
    finally:
        conn.close()

# 2FA setup page
@app.route('/setup_2fa')
def setup_2fa():
    if 'username' not in session or 'totp_secret' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    totp_secret = session['totp_secret']
    
    # Create provisioning URI for QR code
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=username,
        issuer_name="SecureChat"
    )
    
    return render_template('setup_2fa.html', 
                          username=username,
                          totp_secret=totp_secret,
                          totp_uri=totp_uri)

# Generate QR code
@app.route('/qrcode')
def generate_qrcode():
    if 'totp_uri' not in request.args:
        return "Missing TOTP URI", 400
    
    # Get the URI from the query string
    totp_uri = request.args.get('totp_uri')
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to bytes buffer
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    # Return image
    return send_file(buffer, mimetype='image/png')

# Service worker route
@app.route('/sw.js')
def service_worker():
    return app.send_static_file('sw.js')

# Create a handler for Vercel serverless function
app.wsgi_app = app.wsgi_app

# Only run the server if the script is executed directly
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5002)
