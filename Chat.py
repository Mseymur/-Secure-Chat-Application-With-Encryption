import sqlite3
import random
import string
import base64
from cryptography.fernet import Fernet
from flask import Flask, request, render_template, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = 'supersecretkey'

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
        FOREIGN KEY (chat_id) REFERENCES chats (chat_id),
        FOREIGN KEY (sender_id) REFERENCES users (id)
    )
    ''')
    conn.commit()
    conn.close()

# Generate encryption key for encrypting messages
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

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
        cursor.execute('SELECT id FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
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
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
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
            encryption_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
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
    cursor.execute('''
        SELECT messages.message, users.username
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE messages.chat_id = ?
    ''', (chat_id,))
    messages = cursor.fetchall()
    conn.close()
    
    decrypted_messages = []
    for message in messages:
        decrypted_message = cipher.decrypt(base64.b64decode(message[0])).decode()
        decrypted_messages.append({'sender': message[1], 'message': decrypted_message})
    
    return jsonify(messages=decrypted_messages)

# Route to send chat messages
@app.route('/send_message/<int:chat_id>', methods=['POST'])
def send_message(chat_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    data = request.get_json()
    message = data['message']
    
    encrypted_message = base64.b64encode(cipher.encrypt(message.encode())).decode()
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO messages (chat_id, sender_id, message) VALUES (?, ?, ?)', (chat_id, user_id, encrypted_message))
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

# Route to logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
