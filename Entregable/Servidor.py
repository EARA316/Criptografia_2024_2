import socket
import threading

def handle_client(client_socket, address):
    print(f"[CONEXIÓN ESTABLECIDA EXITOSA] {address[0]}:{address[1]}")

    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                print(f"[CONEXIÓN CERRADA] {address[0]}:{address[1]}")
                break
            print(f"[{address[0]}:{address[1]}] {message}")
            # Enviar el mensaje a todos los clientes excepto al remitente
            broadcast(message, client_socket)
        except Exception as e:
            print(f"Error: {e}")
            break

    client_socket.close()

def broadcast(message, sender_socket):
    for client_socket in clients:
        if client_socket != sender_socket:
            try:
                client_socket.send(message.encode('utf-8'))
            except Exception as e:
                print(f"Error al enviar mensaje: {e}")
                client_socket.close()
                clients.remove(client_socket)

def start_server():
    global clients
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 5555))
    server.listen(5)
    print("[ESPERANDO CONEXIONES]" )
    print("Servidor CRIPTO en ejecución...")

    clients = []

    while True:
        client_socket, address = server.accept()
        clients.append(client_socket)
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()

start_server()
