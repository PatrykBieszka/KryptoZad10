import hashlib
import socket
import sys


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

HOST = '127.0.0.1'
PORT = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))
    print("Połączono z serwerem")

    while True:
        action = input("Wybierz akcję (login/register/exit): ")

        if action == "exit":
            print("Zamykanie klienta...")
            sys.exit()

        username = input("Podaj nazwę użytkownika: ")
        password = input("Podaj hasło: ")
        hashed_password = hash_password(password)
        message = f"{action}:{username}:{hashed_password}"
        client_socket.sendall(message.encode())
        response = client_socket.recv(1024).decode()
        print('Odpowiedź serwera:', response)