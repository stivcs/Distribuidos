import socket
import threading
import ssl
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

#IP y PUERTO del servidor
IP = "192.168.1.8"
PORT = 12345


# Generar claves RSA para el cliente
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serializar la clave pública
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def run_client():
    # Solicitar el nombre de usuario por consola
    username = input("Ingresa tu nombre de usuario: ").strip()
    if not username:
        print("El nombre de usuario no puede estar vacío.")
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Configurar SSL para el cliente
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False  # Deshabilitado para certificado autofirmado
    context.verify_mode = ssl.CERT_NONE  # Deshabilitado para pruebas
    secure_client_socket = context.wrap_socket(client_socket)

    try:
        secure_client_socket.connect((IP, PORT))
        
        # Recibir la clave pública del servidor
        server_public_pem = secure_client_socket.recv(4096)
        server_public_key = serialization.load_pem_public_key(server_public_pem)

        # Enviar clave pública y nombre de usuario al servidor
        secure_client_socket.send(public_pem)
        secure_client_socket.send(username.encode())

        # Diccionario para almacenar claves públicas de otros clientes
        other_clients = {}

        def receive_messages():
            while True:
                try:
                    # Recibir mensajes o claves públicas de otros clientes
                    data = secure_client_socket.recv(4096)
                    if not data:
                        break
                    
                    # Si son 2-3 bytes, probablemente es el tamaño del siguiente mensaje
                    if len(data) <= 3:
                        continue
                    
                    # Si es una clave pública (contiene 'PUBLIC KEY')
                    if b'PUBLIC KEY' in data:
                        client_public_key = serialization.load_pem_public_key(data)
                        client_username = secure_client_socket.recv(1024).decode()
                        other_clients[client_username] = client_public_key
                        print(f"Cliente conectado: {client_username}")
                    else:
                        # Es un mensaje con el nombre del remitente
                        sender_username = data.decode()
                        encrypted_message = secure_client_socket.recv(4096)
                        decrypted_message = private_key.decrypt(
                            encrypted_message,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        print(f"{sender_username}: {decrypted_message.decode()}")  # Mostrar nombre y mensaje
                except Exception as e:
                    print(f"Error recibiendo mensaje: {e}")
                    break

        # Iniciar hilo para recibir mensajes
        receive_thread = threading.Thread(target=receive_messages)
        receive_thread.daemon = True
        receive_thread.start()

        # Enviar mensajes
        print("Ya puedes escribir (usa 'salir' para desconectarte):")
        while True:
            message = input()
            if message.lower() == "salir":
                break
                
            # Cifrar mensaje para el servidor
            encrypted_for_server = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            secure_client_socket.send(encrypted_for_server)

            # Cifrar mensaje para otros clientes
            encrypted_for_clients = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            secure_client_socket.send(encrypted_for_clients)

    except Exception as e:
        print(f"Error en el cliente: {e}")
    finally:
        secure_client_socket.close()
        print("Desconectado del servidor.")

if __name__ == "__main__":
    run_client()