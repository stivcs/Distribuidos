import socket
import threading

# Lista para mantener las conexiones de los clientes
clientes = {}

# Función para manejar la comunicación con cada cliente
def manejar_cliente(cliente_socket, direccion):
    print(f"[+] Nueva conexión de {direccion}")
    # Recibir el nombre o identificador del cliente
    nombre_cliente = cliente_socket.recv(1024).decode('utf-8')
    clientes[nombre_cliente] = cliente_socket
    print(f"[+] {nombre_cliente} se ha conectado desde {direccion}")

    while True:
        try:
            mensaje = cliente_socket.recv(1024).decode('utf-8')
            if mensaje:
                print(f"Mensaje recibido de {nombre_cliente}: {mensaje}")
                # Reenviar el mensaje a todos los clientes conectados con el nombre del remitente
                for nombre, socket_cliente in clientes.items():
                    if socket_cliente != cliente_socket:
                        socket_cliente.send(f"{nombre_cliente}: {mensaje}".encode('utf-8'))
            else:
                # Si no se recibe mensaje, se cierra la conexión
                print(f"[-] {nombre_cliente} se ha desconectado")
                del clientes[nombre_cliente]
                cliente_socket.close()
                break
        except:
            print(f"[-] {nombre_cliente} se ha desconectado abruptamente")
            del clientes[nombre_cliente]
            cliente_socket.close()
            break

# Configuración del servidor
def iniciar_servidor():
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = "192.168.1.11" # Cambiar por la dirección IP de la máquina servidor
    server_port = 1234 # Cambiar por el puerto deseado
    servidor.bind((server_ip,server_port))  # Escucha en todas las interfaces en el puerto 12345
    servidor.listen(5)
    print("[*] Servidor escuchando en el puerto 12345")

    while True:
        cliente_socket, direccion = servidor.accept()
        # Iniciar un hilo para manejar la conexión del cliente
        hilo = threading.Thread(target=manejar_cliente, args=(cliente_socket, direccion))
        hilo.start()

if __name__ == "__main__":
    iniciar_servidor()