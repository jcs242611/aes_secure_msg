import pickle
import argparse
import configparser
import socket
from helper import generate_key, encrypt_data

config = configparser.ConfigParser()
config.read('config.ini')
shared_password = config.get('security', 'SHARED_PASSWORD')
shared_salt = config.get('security', 'SHARED_SALT')


def send_msg(server_address):
    key = generate_key(shared_password.encode(), shared_salt.encode())

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(server_address)
        print("[INFO] Connection established with server.")
    except Exception as e:
        print(e)
        return

    username = input("[PROMPT] Enter your username: ")
    encrypted_username, iv_username = encrypt_data(username.encode(), key)
    while True:
        msg = input(
            "[PROMPT] Enter message you want to send (type 'q' to quit): ")
        if msg.lower() == 'q':
            client_socket.close()
            print("[END] Connection closed!")
            break
        else:
            encrypted_msg, iv_msg = encrypt_data(msg.encode(), key)
            client_socket.sendall(pickle.dumps(
                (encrypted_username, iv_username, encrypted_msg, iv_msg)))
            print("[INFO] Message sent.")


parser = argparse.ArgumentParser(
    description='Sending encrypted messages using AES')
parser.add_argument('server_ip', help='IP address of the server')
parser.add_argument('server_port', type=int, help='Port number of the server')

args = parser.parse_args()

send_msg((args.server_ip, args.server_port))
