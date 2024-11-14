import os
import sqlite3
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend


def generate_key(password, salt):
    key_derivation_function = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return key_derivation_function.derive(password)


def encrypt_data(data, key):
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()

    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data, iv


def decrypt_data(data, iv, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(data) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data


def setup_database():
    conn = sqlite3.connect('messages.db')
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        user_id BLOB,
        message BLOB,
        iv BLOB,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()


def store_message(user_id, message, iv):
    conn = sqlite3.connect('messages.db')
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO messages (user_id, message, iv, timestamp)
    VALUES (?, ?, ?, ?)
    """, (user_id, message, iv, datetime.now()))
    conn.commit()
    conn.close()
