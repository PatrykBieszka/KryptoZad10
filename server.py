import hashlib
import uuid
import socket


HOST = '127.0.0.1'
PORT = 12345

accounts = {}

def add_user(username, password):
    salt = uuid.uuid4().hex
    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
    accounts[username] = {'salt': salt, 'password_hash': hashed_password}

def authenticate_user(username, password_hash):
    if username in accounts:
        user = accounts[username]
        stored_password_hash = hashlib.sha256((password_hash + user['salt']).encode()).hexdigest()
        if stored_password_hash == user['password_hash']:
            return True
    return False

# Utworzenie gniazda serwera
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"Serwer nasłuchuje na {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        with conn:
            print('Połączono przez', addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                decoded_data = data.decode().split(":")
                action = decoded_data[0]
                if action == "login":
                    username = decoded_data[1]
                    password_hash = decoded_data[2]
                    if authenticate_user(username, password_hash):
                        response = "Zalogowano"
                    else:
                        response = "Błąd logowania"
                    conn.sendall(response.encode())
                elif action == "register":
                    username = decoded_data[1]
                    password = decoded_data[2]
                    add_user(username, password)
                    response = "Utworzono użytkownika"
                    conn.sendall(response.encode())