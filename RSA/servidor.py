import socket
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Generar claves RSA para el servidor
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()

# Serializar la clave pública del servidor
server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Diccionario para almacenar clientes (conexión, clave pública y usuario)
clients = {}
clients_lock = threading.Lock()

# Configurar el socket del servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('192.168.60.28', 12345))
server_socket.listen()

print("Servidor iniciado. Esper-stage conexiones...")

# Función para manejar cada cliente
def handle_client(conn, addr):
    try:
        # Enviar la clave pública del servidor al cliente
        conn.send(server_public_pem)
        
        # Recibir la clave pública y el nombre de usuario del cliente
        public_pem = conn.recv(4096)
        public_key = serialization.load_pem_public_key(public_pem)
        username = conn.recv(1024).decode()
        
        # Agregar cliente al diccionario
        with clients_lock:
            clients[conn] = {'public_key': public_key, 'username': username}
            print(f"Cliente '{username}' conectado desde {addr}. Total de clientes: {len(clients)}")
            
            # Enviar la lista de claves públicas y nombres de usuario de los otros clientes
            for other_conn, info in clients.items():
                if other_conn != conn:
                    conn.send(info['public_key'].public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                    conn.send(info['username'].encode())
                    other_conn.send(public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                    other_conn.send(username.encode())

        # Recibir y procesar mensajes
        while True:
            # Recibir mensaje cifrado para el servidor
            encrypted_for_server = conn.recv(4096)
            if not encrypted_for_server:
                break
            
            # Descifrar el mensaje para el servidor
            decrypted_message = server_private_key.decrypt(
                encrypted_for_server,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            sender_username = clients[conn]['username']
            print(f"Mensaje de '{sender_username}': {decrypted_message.decode()}")

            # Recibir mensaje cifrado para los otros clientes y reenviarlo
            encrypted_for_clients = conn.recv(4096)
            if not encrypted_for_clients:
                break
            
            with clients_lock:
                for other_conn in clients:
                    if other_conn != conn:
                        other_conn.send(sender_username.encode())
                        other_conn.send(encrypted_for_clients)
    except Exception as e:
        print(f"Error con cliente {addr}: {e}")
    finally:
        with clients_lock:
            if conn in clients:
                username = clients[conn]['username']
                del clients[conn]
                print(f"Cliente '{username}' desconectado. Total de clientes: {len(clients)}")
        conn.close()

# Aceptar conexiones de clientes
def accept_connections():
    while True:
        try:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()
        except KeyboardInterrupt:
            break

# Iniciar el servidor
try:
    accept_thread = threading.Thread(target=accept_connections)
    accept_thread.start()
    accept_thread.join()
except KeyboardInterrupt:
    print("\nServidor detenido.")
finally:
    server_socket.close()