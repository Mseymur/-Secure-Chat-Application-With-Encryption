import os, sys; sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import sqlite3
import base64
import Chat
import pytest

@pytest.fixture()
def client(tmp_path):
    # Use temporary database file
    Chat.DB_NAME = str(tmp_path / "test.db")
    Chat.init_db()
    Chat.app.config['TESTING'] = True
    with Chat.app.test_client() as client:
        yield client


def add_sample_data():
    conn = sqlite3.connect(Chat.DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('user1', 'pass'))
    user_id = cursor.lastrowid
    cursor.execute(
        "INSERT INTO chats (encryption_key, user1_id, chat_name) VALUES (?, ?, ?)",
        ('key123', user_id, 'test'),
    )
    chat_id = cursor.lastrowid
    msg = base64.b64encode(Chat.cipher.encrypt(b'hello')).decode()
    cursor.execute(
        "INSERT INTO messages (chat_id, sender_id, message) VALUES (?, ?, ?)",
        (chat_id, user_id, msg),
    )
    conn.commit()
    conn.close()
    return chat_id, user_id


def test_delete_chat_removes_chat_and_messages(client):
    chat_id, user_id = add_sample_data()

    # login user in session
    with client.session_transaction() as sess:
        sess['username'] = 'user1'
        sess['user_id'] = user_id

    response = client.post(f'/delete_chat/{chat_id}')
    assert response.status_code == 200

    conn = sqlite3.connect(Chat.DB_NAME)
    cur = conn.cursor()
    cur.execute('SELECT 1 FROM chats WHERE chat_id = ?', (chat_id,))
    assert cur.fetchone() is None
    cur.execute('SELECT 1 FROM messages WHERE chat_id = ?', (chat_id,))
    assert cur.fetchone() is None
    conn.close()
