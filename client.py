import socket
import threading
import customtkinter as ctk

def receive_messages():
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if message:
                chat_textbox.insert(ctk.END, f"{message}\n")
        except:
            break

def send_message():
    message = message_entry.get()
    if message:
        client.send(message.encode('utf-8'))
        chat_textbox.insert(ctk.END, f"Me: {message}\n")
        message_entry.delete(0, ctk.END)

def connect_to_server():
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host_entry.get(), int(port_entry.get())))
    credentials = f"{username_entry.get()}:{password_entry.get()}"
    client.send(credentials.encode('utf-8'))
    auth_response = client.recv(1024).decode('utf-8')
    if auth_response == "AUTH_SUCCESS":
        status_label.configure(text="Connected", fg_color="green")
        receive_thread = threading.Thread(target=receive_messages)
        receive_thread.start()
    else:
        status_label.configure(text="Authentication Failed", fg_color="red")
        client.close()

def disconnect_from_server():
    client.close()
    status_label.configure(text="Disconnected", fg_color="red")

def toggle_connection():
    if connect_switch.get():
        connect_to_server()
        connect_switch.configure(text="Disconnect")
    else:
        disconnect_from_server()
        connect_switch.configure(text="Connect")

app = ctk.CTk()
app.title("Client")

# Create a frame for the login section
login_frame = ctk.CTkFrame(app)
login_frame.pack(pady=10, padx=10, fill="x")

login_label = ctk.CTkLabel(login_frame, text="Login", font=("Helvetica", 16, "bold"))
login_label.grid(row=0, column=0, columnspan=4, pady=5)

host_label = ctk.CTkLabel(login_frame, text="Host:")
host_label.grid(row=1, column=0, padx=5, pady=5)
host_entry = ctk.CTkEntry(login_frame)
host_entry.grid(row=1, column=1, padx=5, pady=5)

port_label = ctk.CTkLabel(login_frame, text="Port:")
port_label.grid(row=1, column=2, padx=5, pady=5)
port_entry = ctk.CTkEntry(login_frame)
port_entry.grid(row=1, column=3, padx=5, pady=5)

username_label = ctk.CTkLabel(login_frame, text="Username:")
username_label.grid(row=2, column=0, padx=5, pady=5)
username_entry = ctk.CTkEntry(login_frame)
username_entry.grid(row=2, column=1, padx=5, pady=5)

password_label = ctk.CTkLabel(login_frame, text="Password:")
password_label.grid(row=2, column=2, padx=5, pady=5)
password_entry = ctk.CTkEntry(login_frame, show="*")
password_entry.grid(row=2, column=3, padx=5, pady=5)

connect_switch = ctk.CTkSwitch(login_frame, text="Connect", command=toggle_connection)
connect_switch.grid(row=3, column=0, columnspan=2, padx=5, pady=10)
status_label = ctk.CTkLabel(login_frame, text="Disconnected", fg_color="red")
status_label.grid(row=3, column=2, columnspan=2, padx=5, pady=10)

# Create a frame for the chat section
chat_frame = ctk.CTkFrame(app)
chat_frame.pack(pady=10, padx=10, fill="both", expand=True)

chat_textbox = ctk.CTkTextbox(chat_frame, width=400, height=200)
chat_textbox.pack(padx=10, pady=5, fill="both", expand=True)

message_entry = ctk.CTkEntry(chat_frame)
message_entry.pack(side="left", padx=10, pady=5, fill="x", expand=True)
send_button = ctk.CTkButton(chat_frame, text="Send", command=send_message)
send_button.pack(side="right", padx=10, pady=5)

app.mainloop()
