import os
import pickle
import argparse
import socket
from helper import generate_key, setup_database, store_message, decrypt_data

shared_password = os.getenv("SHARED_PASSWORD")
shared_salt = os.getenv("SHARED_SALT")


def receive_msg(server_address):
    setup_database()
    print("[INFO] Database setup done.")

    key = generate_key(shared_password.encode(), shared_salt.encode())

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(1)
    print("[INFO] Server is listening...")

    while True:
        client_socket, _ = server_socket.accept()
        print("[INFO] Connected to client.")

        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    print("[END] Client has disconnected!")
                    break

                encrypted_username, iv_username, encrypted_msg, iv_msg = pickle.loads(
                    data)
                username = decrypt_data(
                    encrypted_username, iv_username, key).decode()

                store_message(username, encrypted_msg, iv_msg)
                print("[INFO] Encrypted message stored in database.")

                msg = decrypt_data(encrypted_msg, iv_msg, key)
                print(f"[MESSAGE] {msg.decode()}")

        except Exception as e:
            print(e)
        finally:
            client_socket.close()


parser = argparse.ArgumentParser(
    description='Receiving encrypted messages using AES 256')
parser.add_argument('server_ip', help='IP address of the server')
parser.add_argument('server_port', type=int, help='Port number of the server')

args = parser.parse_args()

receive_msg((args.server_ip, args.server_port))
