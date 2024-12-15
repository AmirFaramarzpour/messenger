import socket
import threading

users = {"user1": "password1", "user2": "password2"}  # Example user credentials
clients = []

def handle_client(client_socket, client_address):
    authenticated = False
    while not authenticated:
        credentials = client_socket.recv(1024).decode('utf-8').split(":")
        username, password = credentials[0], credentials[1]
        if username in users and users[username] == password:
            client_socket.send("AUTH_SUCCESS".encode('utf-8'))
            authenticated = True
        else:
            client_socket.send("AUTH_FAIL".encode('utf-8'))
            remove(client_socket)
            break
    if authenticated:
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if message:
                    print(f"{client_address[0]}: {message}")  # Print the message to server terminal
                    broadcast(f"{username}: {message}", client_socket)
                else:
                    remove(client_socket)
                    break
            except:
                continue

def broadcast(message, connection):
    for client in clients:
        if client != connection:
            try:
                client.send(message.encode('utf-8'))
            except:
                remove(client)

def remove(connection):
    if connection in clients:
        clients.remove(connection)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))  # Change the port if needed
    server.listen(100)
    server_ip = socket.gethostbyname(socket.gethostname())
    print(f"Server started at {server_ip}:5555")
    print("Waiting for connections...")

    while True:
        client_socket, client_address = server.accept()
        clients.append(client_socket)
        print(f"{client_address[0]} connected")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()

if __name__ == "__main__":
    start_server()
