# SecureChat - End-to-End Encrypted Messaging

SecureChat is a web-based messaging application that provides end-to-end encryption for secure communications. Built with Python Flask and Socket.IO, it ensures that your messages can only be read by you and your intended recipients.

## Features

- **End-to-End Encryption**: All messages are encrypted using Fernet symmetric encryption
- **Secure Account Management**: Strong password requirements and secure storage
- **Real-time Messaging**: Instant message delivery using Socket.IO
- **User-Friendly Interface**: Clean, responsive design for desktop and mobile
- **Privacy-Focused**: No message content is ever stored in plaintext

## Security Features

- Password hashing using Werkzeug's security functions
- Encrypted message storage - messages are only decrypted client-side
- Secure key exchange mechanism
- Session management for authenticated users
- Input validation and sanitization

## Installation

### Prerequisites

- Python 3.7+
- SQLite3

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-chat.git
   cd secure-chat
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Run the application:
   ```
   python Chat.py
   ```

5. Access the application at `http://localhost:5000`

## Usage

### Creating a New Chat

1. Register or log in to your account
2. Click "New Chat" to create a new encrypted chat
3. Share the generated encryption key with your intended recipient through a secure channel
4. Start messaging securely!

### Joining an Existing Chat

1. Ask the chat creator for the encryption key
2. Click "Join Chat" and enter the encryption key
3. You will be added to the chat and can start messaging

### Security Best Practices

- Always share encryption keys through secure channels, not in the chat itself
- Use strong, unique passwords for your account
- Log out when using shared devices
- Keep your browser and system updated

## Project Structure

```
secure-chat/
├── Chat.py                # Main application file
├── static/                # Static assets
│   └── styles.css         # CSS styles
├── templates/             # HTML templates
│   ├── chat.html          # Chat list page
│   ├── chat_room.html     # Individual chat room
│   ├── error.html         # Error page
│   ├── home.html          # Home/landing page
│   ├── layout.html        # Base layout template
│   ├── login.html         # Login page
│   ├── profile.html       # User profile page
│   ├── signup.html        # Registration page
│   └── welcome.html       # New user welcome page
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## Technical Details

- **Backend**: Python Flask
- **Database**: SQLite3
- **Real-time Communication**: Socket.IO
- **Encryption**: cryptography.fernet
- **Frontend**: HTML, CSS, JavaScript
- **Authentication**: Session-based with password hashing

## Development Roadmap

- [ ] Group chat support
- [ ] Message read receipts
- [ ] File sharing capabilities
- [ ] Mobile app version
- [ ] End-to-end encrypted voice/video calls

## Security Considerations

This application is designed for educational purposes and may need additional security hardening before use in sensitive environments. Consider the following for production use:

- Use HTTPS with proper certificate validation
- Implement additional authentication factors
- Regular security audits and penetration testing
- Proper key management infrastructure
- Rate limiting and additional anti-abuse measures

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

