import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Generar claves RSA para el cliente
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serializar la clave pública
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Configurar el socket del cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.60.28', 12345))

# Recibir la clave pública del servidor
server_public_pem = client_socket.recv(4096)
server_public_key = serialization.load_pem_public_key(server_public_pem)

# Diccionario para almacenar claves públicas de otros clientes
other_clients = {}
clients_lock = threading.Lock()

# Interfaz gráfica
root = tk.Tk()
root.title("Chat RSA")
root.geometry("400x500")

# Área de texto para mostrar mensajes
chat_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=40, height=20)
chat_display.pack(pady=10)

# Campo de entrada para el nombre de usuario
username_label = tk.Label(root, text="Ingresa tu nombre de usuario:")
username_label.pack()
username_entry = tk.Entry(root, width=30)
username_entry.pack(pady=5)

# Campo de entrada para mensajes
message_entry = tk.Entry(root, width=30)
message_entry.pack(pady=5)

# Botón para enviar mensajes
send_button = tk.Button(root, text="Enviar", state=tk.DISABLED)
send_button.pack(pady=5)

# Función para registrar el usuario y habilitar el chat
def register_user():
    username = username_entry.get().strip()
    if username:
        client_socket.send(public_pem)
        client_socket.send(username.encode())
        chat_display.insert(tk.END, f"Registrado como '{username}'\n")
        username_entry.config(state=tk.DISABLED)
        send_button.config(state=tk.NORMAL)
        root.title(f"Chat RSA - {username}")

# Función para enviar mensajes
def send_message():
    message = message_entry.get().strip().encode()
    if message:
        with clients_lock:
            if not other_clients:
                chat_display.insert(tk.END, "No hay otros clientes conectados aún.\n")
            else:
                encrypted_for_server = server_public_key.encrypt(
                    message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                client_socket.send(encrypted_for_server)

                for key in other_clients.values():
                    encrypted_for_clients = key.encrypt(
                        message,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    client_socket.send(encrypted_for_clients)
        message_entry.delete(0, tk.END)

# Función para recibir mensajes y claves públicas
def receive_messages():
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                chat_display.insert(tk.END, "Conexión cerrada por el servidor.\n")
                break
            if len(data) > 256:
                new_public_key = serialization.load_pem_public_key(data)
                new_username = client_socket.recv(1024).decode()
                with clients_lock:
                    other_clients[new_username] = new_public_key
                chat_display.insert(tk.END, f"Cliente '{new_username}' se ha conectado.\n")
            else:
                sender_username = data.decode()
                encrypted_message = client_socket.recv(4096)
                decrypted_message = private_key.decrypt(
                    encrypted_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                chat_display.insert(tk.END, f"{sender_username}: {decrypted_message.decode()}\n")
                chat_display.see(tk.END)
        except:
            chat_display.insert(tk.END, "Error en la conexión.\n")
            break

# Configurar eventos
username_entry.bind("<Return>", lambda event: register_user())
message_entry.bind("<Return>", lambda event: send_message())
send_button.config(command=send_message)

# Iniciar hilo para recibir mensajes
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

# Manejar cierre de la ventana
def on_closing():
    client_socket.close()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

# Iniciar la interfaz gráfica
root.mainloop()