Problem Statement:

In the digital age, secure communication is paramount. Many messaging platforms exist, but few provide robust encryption, simple usability, and real-time messaging for two users within a manageable scope for educational purposes or small-scale deployments. The challenge is to create a secure chat application where users can:

* Sign up and Log in: Users should be able to register with unique usernames and passwords, and log in to access their chat sessions.

* Create and Join Chats: Users should be able to create new chat sessions with unique encryption keys or join existing ones using these keys.

* Real-Time Messaging: Users should be able to send and receive messages in **real-time**.

* Message Encryption: Messages should be encrypted before being stored in the database and decrypted when retrieved to ensure privacy and security.

* Manage Chats: Users should be able to delete chat sessions, which removes all associated messages securely.

Solution:

The Secure Chat Application addresses the problem by providing a simple, user-friendly platform with the following features:

User Authentication:

* Sign-Up: New users can register with a unique username and password.
* Login: Returning users can log in with their credentials.

Chat Management:

* Create Chat: Users can create a new chat session, generating a unique encryption key to share with another user.
* Join Chat: Users can join an existing chat session using the provided encryption key.

Real-Time Messaging:

* Send Messages: Users can send messages that are instantly visible to the other participant in the chat.
* Receive Messages: Messages are fetched from the server and displayed in real-time.

Encryption:

* Encrypt Messages: Messages are encrypted using the cryptography library before being stored in the database.
* Decrypt Messages: Messages are decrypted when retrieved from the database to ensure that only authorized users can read them.

Delete Chats:

* Users can delete a chat session, which removes all messages associated with that chat from the database, ensuring no data remnants are left behind.

Technical Implementation:

* Flask Web Framework: Provides the backend server and handles HTTP requests, routing, and user sessions.
* SQLite Database: Stores user information, chat sessions, and encrypted messages.
* Cryptography Library: Used for encrypting and decrypting messages to ensure data security.
* JavaScript and AJAX: Enables real-time messaging by periodically fetching new messages and sending user input to the server.
* HTML Templates: Rendered by Flask, these templates provide the user interface for login, sign-up, chat management, and the chat room.

## Setup Instructions

1. Create and activate a Python virtual environment.

```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
python Chat.py
```

The app will start on `http://localhost:5000`.

### Features
- Passwords are hashed using Werkzeug for secure storage.
- Each chat uses its own encryption key which is persisted in the database.
- Real-time messaging is handled by Flask-SocketIO.

