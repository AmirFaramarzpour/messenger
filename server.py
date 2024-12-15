import socket
import threading
import http.server
import socketserver
import customtkinter as ctk
from base64 import b64decode
import tkinter as tk
from tkinter import filedialog
from base64 import b64encode

users = {"amir": "amir", "movie": "movie", "admin":"root","guest":"guest"}  # Example user credentials
clients = []
server = None
httpd = None
shared_directory = "."

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
                    log_message(f"{client_address[0]}: {message}")
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
    global server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', int(port_entry.get())))
    server.listen(100)
    server_ip = socket.gethostbyname(socket.gethostname())
    log_message(f"Socket server started at {server_ip}:{port_entry.get()}")
    log_message("Waiting for connections...")

    while True:
        client_socket, client_address = server.accept()
        clients.append(client_socket)
        log_message(f"{client_address[0]} connected")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()

def stop_server():
    global server
    if server:
        for client in clients:
            client.close()
        server.close()
        log_message("Server stopped.")

def toggle_server():
    if server_switch.get():
        server_thread = threading.Thread(target=start_server)
        server_thread.start()
    else:
        stop_server()

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if self.headers.get('Authorization') is None:
            self.do_AUTHHEAD()
            self.wfile.write(b'No auth header received')
        else:
            auth_header = self.headers.get('Authorization')
            auth_decoded = b64decode(auth_header.split(' ')[1]).decode('utf-8')
            username, password = auth_decoded.split(':')

            if users.get(username) == password:
                super().do_GET()
            else:
                self.do_AUTHHEAD()
                self.wfile.write(b'Not authenticated')


    def log_message(self, format, *args):
        log_http_message(f"GET request: {self.client_address[0]} - {format % args}")

def start_http_server():
    global httpd
    handler = AuthHandler
    httpd = socketserver.TCPServer(("0.0.0.0", int(http_port_entry.get())), handler)
    http_server_ip = socket.gethostbyname(socket.gethostname())
    log_http_message(f"HTTP server started at {http_server_ip}:{http_port_entry.get()}")
    httpd.serve_forever()

def stop_http_server():
    global httpd
    if httpd:
        httpd.shutdown()
        log_http_message("HTTP server stopped.")

def toggle_http_server():
    if http_server_switch.get():
        http_server_thread = threading.Thread(target=start_http_server)
        http_server_thread.start()
    else:
        stop_http_server()

def select_directory():
    global shared_directory
    directory = filedialog.askdirectory()
    if directory:
        shared_directory = directory
        shared_directory_entry.delete(0, tk.END)
        shared_directory_entry.insert(0, shared_directory)
        log_message(f"Selected directory: {shared_directory}")

def add_user():
    username = new_user_entry.get()
    password = new_password_entry.get()
    if username and password:
        users[username] = password
        update_user_list()
        log_message(f"Added user: {username}")

def update_user_list():
    user_textbox.configure(state=tk.NORMAL)
    user_textbox.delete(1.0, tk.END)
    for user in users:
        user_textbox.insert(tk.END, f"{user}\n")
    user_textbox.configure(state=tk.DISABLED)

def log_message(message):
    log_textbox.insert(ctk.END, f"{message}\n")
    log_textbox.see(ctk.END)

def log_http_message(message):
    http_log_textbox.insert(ctk.END, f"{message}\n")
    http_log_textbox.see(ctk.END)

app = ctk.CTk()
app.title("ConnectPlus [Server Side GUI]")
app.geometry("700x700")
app.resizable(False, False)


# Set the main window color using a custom frame
main_frame = ctk.CTkFrame(app, fg_color="#7C8363")
main_frame.pack(fill="both", expand=True, padx=20, pady=5)

# Server control section
server_control_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
server_control_frame.pack(pady=1, fill="x")

port_label = ctk.CTkLabel(server_control_frame, text="Port:", font=("Trebuchet MS", 12))
port_label.grid(row=0, column=0, padx=5, pady=5)
port_entry = ctk.CTkEntry(server_control_frame, corner_radius=10, placeholder_text="Enter port number")
port_entry.grid(row=0, column=1, padx=5, pady=5)

server_switch = ctk.CTkSwitch(server_control_frame, text="Start Socket Module (Messenger)", font=("Trebuchet MS", 12), command=toggle_server)
server_switch.grid(row=0, column=2, padx=5, pady=5)

# HTTP server control section
http_server_control_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
http_server_control_frame.pack(pady=1, fill="x")

http_port_label = ctk.CTkLabel(http_server_control_frame, text="HTTP Port:", font=("Trebuchet MS", 12))
http_port_label.grid(row=0, column=0, padx=5, pady=5)
http_port_entry = ctk.CTkEntry(http_server_control_frame, corner_radius=10, placeholder_text="Enter port number")
http_port_entry.grid(row=0, column=1, padx=5, pady=5)



http_server_switch = ctk.CTkSwitch(http_server_control_frame, text="Start HTTP Server", font=("Trebuchet MS", 12), command=toggle_http_server)
http_server_switch.grid(row=0, column=3, padx=5, pady=5)

shared_directory_label = ctk.CTkLabel(http_server_control_frame, text="Shared Directory:", font=("Trebuchet MS", 12))
shared_directory_label.grid(row=1, column=0, padx=5, pady=5)
shared_directory_entry = ctk.CTkEntry(http_server_control_frame, corner_radius=10, placeholder_text="Select directory")
shared_directory_entry.grid(row=1, column=1, columnspan=1, padx=5, pady=5, sticky="ew")
browse_button = ctk.CTkButton(http_server_control_frame, text="Browse", font=("Trebuchet MS", 12), command=select_directory, corner_radius=10)
browse_button.grid(row=1, column=3, padx=5, pady=5)





# User management section
user_management_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
user_management_frame.pack(pady=1, fill="x")

new_user_label = ctk.CTkLabel(user_management_frame, text="New User:", font=("Trebuchet MS", 12))
new_user_label.grid(row=0, column=0, padx=5, pady=5)
new_user_entry = ctk.CTkEntry(user_management_frame, corner_radius=10, placeholder_text="Enter username")
new_user_entry.grid(row=0, column=1, padx=5, pady=5)

new_password_label = ctk.CTkLabel(user_management_frame, text="New Password:", font=("Trebuchet MS", 12))
new_password_label.grid(row=0, column=2, padx=5, pady=5)
new_password_entry = ctk.CTkEntry(user_management_frame, corner_radius=10, show="*", placeholder_text="Enter password")
new_password_entry.grid(row=0, column=3, padx=5, pady=5)

add_user_button = ctk.CTkButton(user_management_frame, text="Add User", command=add_user, corner_radius=10, font=("Trebuchet MS", 12))
add_user_button.grid(row=0, column=4, padx=5, pady=5)

user_list_label = ctk.CTkLabel(user_management_frame, text="Users:", font=("Trebuchet MS", 12))
user_list_label.grid(row=1, column=0, padx=5, pady=5)
user_textbox = ctk.CTkTextbox(user_management_frame, width=50, height=100, corner_radius=10, state=tk.DISABLED)
user_textbox.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky="ew")
update_user_list()

# Server log section
log_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
log_frame.pack(pady=1, fill="both", expand=True)

log_label = ctk.CTkLabel(log_frame, text="Server Logs", text_color="#31473A", font=("Trebuchet MS", 14, "bold"),fg_color="#EDF4F2",corner_radius=10)
log_label.pack(pady=(10, 0))

log_textbox = ctk.CTkTextbox(log_frame, width=200, height=100, corner_radius=10)
log_textbox.pack(padx=10, pady=5, fill="both", expand=True)

# HTTP request log section
http_log_frame = ctk.CTkFrame(main_frame, fg_color="#31473A")
http_log_frame.pack(pady=1, fill="both", expand=True)

http_log_label = ctk.CTkLabel(http_log_frame, text="HTTP Server Logs", text_color="#31473A", font=("Trebuchet MS", 14, "bold"),fg_color="#EDF4F2",corner_radius=10)
http_log_label.pack(pady=(10, 0))

http_log_textbox = ctk.CTkTextbox(http_log_frame, width=200, height=100, corner_radius=10)
http_log_textbox.pack(padx=10, pady=5, fill="both", expand=True)

# Add copyright label with text wrapping
copyright_label = ctk.CTkLabel(
    main_frame, 
    text="© 2025 Amir Faramarzpour.\nGitHub.com/AmirFaramarzpour", 
    text_color="white", 
    font=("Trebuchet MS", 12, "bold"),
    corner_radius=4, 
    wraplength=380  # Set wrap length to fit within the right frame
)
copyright_label.pack(pady=(3, 3))

app.mainloop()
