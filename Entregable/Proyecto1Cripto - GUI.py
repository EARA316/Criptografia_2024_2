import os
import hashlib
import socket
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2  # Importamos PBKDF2 para la clave simetrica
import base64
import threading

main_frame = None  # Declaramos main_frame como una variable global
client_socket = None
secret_key = None
PRIVATE_KEY_FILE = None
PUBLIC_KEY_FILE = None
RECEIVER_PUBLIC_KEY_FILE = None

# Función para generar un par de claves RSA (privada y pública)
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Función para guardar una clave en un archivo
def save_key_to_file(key, filename):
    with open(filename, "wb") as f:
        f.write(key)

# Función para cargar una clave desde un archivo previamente creado 
def load_key_from_file(filename):
    if filename is None:
        return None
    try:
        with open(filename, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print("[ALERTA] Archivo no encontrado:", filename)
        return None

# Función para generar y guardar claves en archivos seleccionados por el usuario
def generate_and_save_keys():
    global PRIVATE_KEY_FILE, PUBLIC_KEY_FILE
    private_key, public_key = generate_keys()
    private_key_filename = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")], title="Guardar clave privada como", initialfile="private_key.pem", confirmoverwrite=True, initialdir=os.path.expanduser('~'))
    if not private_key_filename:
        return
    public_key_filename = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")], title="Guardar clave pública como", initialfile="public_key.pem", confirmoverwrite=True, initialdir=os.path.expanduser('~'))
    if not public_key_filename:
        return
    try:
        save_key_to_file(private_key, private_key_filename)
        save_key_to_file(public_key, public_key_filename)
        PRIVATE_KEY_FILE = private_key_filename
        PUBLIC_KEY_FILE = public_key_filename
        messagebox.showinfo("Claves generadas", f"Claves generadas y guardadas en {private_key_filename} y {public_key_filename}.")
        received_messages_text.insert(tk.END, "[SISTEMA] Claves generadas y guardadas.\n")
    except Exception as e:
        messagebox.showerror("Error al guardar las claves", f"Ocurrió un error al guardar las claves: {str(e)}")

# Función para derivar una clave simétrica a partir de una contraseña y una sal
def derive_symmetric_key(password, salt):
    key = PBKDF2(password.encode(), salt, dkLen=32, count=100000, prf=lambda p, s: hashlib.sha256(p + s).digest())
    return key

# Función para generar una clave simétrica a partir de una contraseña
def generate_symmetric_key(password, salt=b'salt', iterations=100000):
    key = derive_symmetric_key(password, salt)
    print("Clave simétrica generada (Secreto):", key)
    return key

# Función para guardar una clave simétrica en un archivo
def save_symmetric_key_to_file(key, filename):
    with open(filename, "wb") as f:
        f.write(key)

# Función para cargar una clave simétrica desde un archivo
def load_symmetric_key_from_file(filename):
    if filename is None:
        return None
    try:
        with open(filename, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print("Archivo no encontrado:", filename)
        return None

# Función para cifrar un mensaje simétricamente
def symmetric_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, cipher.nonce, tag

# Función para descifrar un mensaje simétricamente
def symmetric_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Función para cifrar un mensaje asimétricamente utilizando la clave pública
def asymmetric_encrypt(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    cipher_text = cipher.encrypt(message.encode())
    return cipher_text

# Función para descifrar un mensaje asimétricamente utilizando la clave privada
def asymmetric_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

# Función para generar el hash de un mensaje
def generate_hash(message):
    hash_object = hashlib.sha256(message.encode())
    return hash_object.hexdigest()

# Función para generar una firma digital de un mensaje utilizando la clave privada
def generate_digital_signature(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

# Función para verificar la firma digital de un mensaje utilizando la clave pública
def verify_digital_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Función para enviar un mensaje al servidor
def send_message(message):
    global client_socket
    
    if client_socket is None:
        messagebox.showerror("Error", "No se ha establecido conexión con el servidor.")
        return
    
    client_socket.sendall(message.encode())


# Función para procesar mensajes recibidos [RECEPTOR]
def receive_message():
    global client_socket
    
    while True:
        received_data = receive_message_from_server()
        if 'message' in received_data:
            print("Mensaje recibido:", received_data)
            
            # Mostrar el mensaje recibido en la interfaz de usuario o realizar otras acciones
            display_received_message(received_data)




# Función para recibir mensajes del servidor
def process_quality_confirmation_message():
    global client_socket
    
    while True:
        received_data = receive_message_from_server()
        if received_data:
            received_data = json.loads(received_data)
            received_message = received_data['message']
            received_signature = base64.b64decode(received_data['signature'])
            print("Received Message:", received_message)

            if verify_digital_signature(received_message, received_signature, PUBLIC_KEY_FILE):
                print("Digital Signature Verified for Received Message")
                received_message = json.loads(received_message)
                decrypted_message = received_message['message']
                print("Decrypted Received Message from true:", decrypted_message)
                received_messages_text.insert(tk.END, f"Server: {decrypted_message}\n")
            else:
                print("Digital Signature Verification Failed for Message [ALERT: THE ELEMENT HAS BEEN COMPROMISED]")

# Función para recibir mensajes desde el servidor
def receive_message_from_server():
    global client_socket
    
    if client_socket is None:
        messagebox.showerror("Error", "No se ha establecido conexión con el servidor.")
        return
    
    data = client_socket.recv(1024)
    return data.decode()


def select_private_key_file():
    global PRIVATE_KEY_FILE
    filename = filedialog.askopenfilename()
    if filename:
        PRIVATE_KEY_FILE = filename
        current_text = private_key_label.cget('text')
        if not current_text.endswith(":"):
            current_text += " "
        private_key_label.config(text=current_text + " " + PRIVATE_KEY_FILE)
        private_key_reset_button.config(state=tk.NORMAL)  # Activar el botón de reseteo
        private_key_button.config(state=tk.DISABLED)  # Desactivar el botón de selección

def select_public_key_file():
    global PUBLIC_KEY_FILE
    filename = filedialog.askopenfilename()
    if filename:
        PUBLIC_KEY_FILE = filename
        current_text = public_key_label.cget('text')
        if not current_text.endswith(":"):
            current_text += " "
        public_key_label.config(text=current_text + " " + PUBLIC_KEY_FILE)
        public_key_reset_button.config(state=tk.NORMAL)  # Activar el botón de reseteo
        public_key_button.config(state=tk.DISABLED)  # Desactivar el botón de selección

def select_receiver_public_key_file():
    global RECEIVER_PUBLIC_KEY_FILE
    filename = filedialog.askopenfilename()
    if filename:
        RECEIVER_PUBLIC_KEY_FILE = filename
        current_text = receiver_public_key_label.cget('text')
        if not current_text.endswith(":"):
            current_text += " "
        receiver_public_key_label.config(text=current_text + " " + RECEIVER_PUBLIC_KEY_FILE)
        receiver_public_key_reset_button.config(state=tk.NORMAL)  # Activar el botón de reseteo
        receiver_public_key_button.config(state=tk.DISABLED)  # Desactivar el botón de selección


def reset_private_key_selection():
    global PRIVATE_KEY_FILE
    PRIVATE_KEY_FILE = None
    private_key_label.config(text="Private Key File:")
    private_key_reset_button.config(state=tk.DISABLED)  # Desactivar el botón de reseteo
    private_key_button.config(state=tk.NORMAL)  # Activar el botón de selección

def reset_public_key_selection():
    global PUBLIC_KEY_FILE
    PUBLIC_KEY_FILE = None
    public_key_label.config(text="Public Key File:")
    public_key_reset_button.config(state=tk.DISABLED)  # Desactivar el botón de reseteo
    public_key_button.config(state=tk.NORMAL)  # Activar el botón de selección

def reset_receiver_public_key_selection():
    global RECEIVER_PUBLIC_KEY_FILE
    RECEIVER_PUBLIC_KEY_FILE = None
    receiver_public_key_label.config(text="Receiver Public Key File:")
    receiver_public_key_reset_button.config(state=tk.DISABLED)  # Desactivar el botón de reseteo
    receiver_public_key_button.config(state=tk.NORMAL)  # Activar el botón de selección

def share_public_key():
    global PUBLIC_KEY_FILE, client_socket
    
    if PUBLIC_KEY_FILE is None:
        tk.messagebox.showerror("Error", "Por favor selecciona un archivo de clave pública.")
        return
    
    if client_socket is None:
        messagebox.showerror("Error", "Primero debes conectarte al servidor.")
        return
    
    public_key = load_key_from_file(PUBLIC_KEY_FILE)
    if public_key:
        send_message(json.dumps({
            'public_key': base64.b64encode(public_key).decode()
        }))
        messagebox.showinfo("Llave pública compartida", "La clave pública ha sido enviada al servidor.")
    else:
        tk.messagebox.showerror("Error", "No se pudo cargar la clave pública.")
        


# Función para mostrar un mensaje recibido en la interfaz gráfica
def display_received_message(message):
    received_messages_text.insert(tk.END, f"Server: {message}\n")

# Función para recibir mensajes del servidor
def receive_message():
    global client_socket
    
    while True:
        received_data = receive_message_from_server()
        if received_data:
            received_data = json.loads(received_data)
            
            # Verificar si el mensaje es un secreto
            if 'secret' in received_data:
                received_secret = received_data['secret']
                print("Received Secret from THE SENDER:", received_secret)
                # Realizar acciones necesarias con el secreto recibido
                
            # Verificar si el mensaje es un mensaje regular
            elif 'message' in received_data:
                received_message_base64 = received_data['message']
                received_message = base64.b64decode(received_message_base64).decode('latin-1')
                print("Received Message from THE SENDER (Base64):", received_message_base64)
                print("Received Message from THE SENDER (Decoded):", received_message)
                # Mostrar mensaje en la interfaz de usuario o realizar otras acciones

            # Verificar si el mensaje es una llave pública
            elif 'public_key' in received_data:
                received_public_key_base64 = received_data['public_key']
                received_public_key = base64.b64decode(received_public_key_base64).decode('latin-1')
                print("Received Public Key from THE SENDER (Base64):", received_public_key_base64)
                print("Received Public Key from THE SENDER (Decoded):", received_public_key)
                # Mostrar llave pública en la interfaz de usuario o realizar otras acciones

            else:
                print("Unknown message format RECEIVED")



# Función para mostrar el mensaje enviado en la GUI
def display_sent_message(message):
    received_messages_text.insert(tk.END, f"Sent: {message}\n")

# Función para imprimir el secreto generado en la GUI
def print_secret():
    global secret_key
    if secret_key:
        received_messages_text.insert(tk.END, f"Secret Key: {secret_key.hex()}\n")
    else:
        received_messages_text.insert(tk.END, "No se ha generado ningún secreto aún.\n")

# Función para seleccionar un archivo de clave pública del receptor
def select_receiver_public_key_file():
    global RECEIVER_PUBLIC_KEY_FILE
    filename = filedialog.askopenfilename()
    if filename:
        RECEIVER_PUBLIC_KEY_FILE = filename
        current_text = receiver_public_key_label.cget('text')
        if not current_text.endswith(":"):
            current_text += " "
        receiver_public_key_label.config(text=current_text + " " + RECEIVER_PUBLIC_KEY_FILE)


# Función para cifrar y enviar el secreto al seleccionar una clave pública del receptor
def encrypt_and_send_secret():
    global client_socket, RECEIVER_PUBLIC_KEY_FILE, secret_key

    if client_socket is None:
        messagebox.showerror("Error", "Primero debes conectarte al servidor.")
        return

    if RECEIVER_PUBLIC_KEY_FILE is None:
        messagebox.showerror("Error", "Por favor selecciona un archivo de clave pública del receptor.")
        return

    if client_socket is None:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect(('127.0.0.1', 5555))
            threading.Thread(target=receive_message).start()  # Iniciar hilo para recibir mensajes
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")
        return

    password = password_entry.get()  # Obtener la contraseña como una cadena
    salt = b'salt'  # Define tu sal aquí o de manera dinámica según tus necesidades

    if not password:
        tk.messagebox.showerror("Error", "Por favor ingresa una contraseña.")
        return

    global secret_key
    secret_key = derive_symmetric_key(password, salt)

    receiver_public_key = load_key_from_file(RECEIVER_PUBLIC_KEY_FILE)

    # Convertir el secreto a una cadena antes de codificarlo en base64
    secret_message = secret_key.hex()

    # Codificar la cadena del secreto en base64
    secret_message_base64 = base64.b64encode(secret_message.encode()).decode()

    encrypted_secret = asymmetric_encrypt(secret_message_base64, receiver_public_key)

    send_message(json.dumps({
        'secret': base64.b64encode(encrypted_secret).decode()
    }))
    received_messages_text.insert(tk.END, "Secreto cifrado y enviado correctamente.\n")

    # Mostrar la clave pública del receptor en la terminal
    print("Clave pública del receptor:", receiver_public_key.decode())
    print("Secreto cifrado:", secret_message_base64)
    encrypted_secret_str = base64.b64encode(encrypted_secret).decode()
    print("Secreto cifrado con la clave pública del receptor:", encrypted_secret_str)




# Función para cifrar y enviar un mensaje al servidor
def encrypt_and_send_message():
    global client_socket
    
    if client_socket is None:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect(('127.0.0.1', 5555))
            threading.Thread(target=receive_message).start()  # Iniciar hilo para recibir mensajes
            threading.Thread(target=process_quality_confirmation_message).start()  # Iniciar hilo para recibir confirmaciones de calidad
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")
        return
    
    password = password_entry.get()
    message = message_entry.get()

    # Validar la entrada del usuario
    if not password:
        tk.messagebox.showerror("Error", "Por favor ingresa una contraseña.")
        return

    if not message:
        tk.messagebox.showerror("Error", "Por favor ingresa un mensaje.")
        return

    if PRIVATE_KEY_FILE is None:
        print("No se ha seleccionado un archivo de clave privada.")
        tk.messagebox.showerror("Error", "No se ha seleccionado ningún archivo de clave pública.")
        return

    if PUBLIC_KEY_FILE is None:
        print("No se ha seleccionado un archivo de clave pública.")
        tk.messagebox.showerror("Error", "No se ha seleccionado ningún archivo de clave pública.")
        return

    # Carga Archivos de LLAVES
    private_key = load_key_from_file(PRIVATE_KEY_FILE)
    public_key = load_key_from_file(PUBLIC_KEY_FILE)

    symmetric_key = generate_symmetric_key(password)

    encrypted_message, nonce, tag = symmetric_encrypt(message, symmetric_key)
    symmetric_key_str = base64.b64encode(symmetric_key).decode()
    encrypted_symmetric_key = asymmetric_encrypt(symmetric_key_str, public_key)

    message_digest = generate_hash(message)
    signature = generate_digital_signature(message, private_key)

    decrypted_symmetric_key_str = asymmetric_decrypt(encrypted_symmetric_key, private_key)
    decrypted_symmetric_key = base64.b64decode(decrypted_symmetric_key_str)
    decrypted_message = symmetric_decrypt(encrypted_message, nonce, tag, decrypted_symmetric_key)
    signature_verified = verify_digital_signature(message, signature, public_key)

    print("")
    print("")
    print("\n Original Message:", message)
    print("Encrypted Message:", encrypted_message)
    print("Decrypted Message:", decrypted_message)
    print("Message Digest:", message_digest)
    print("Digital Signature Verified:", signature_verified)

    send_message(json.dumps({
        'message': base64.b64encode(encrypted_message).decode(),
        'signature': base64.b64encode(signature).decode()
    }))

    if signature_verified:
        display_sent_message(message)  # Mostrar el mensaje enviado en la GUI
        received_messages_text.insert(tk.END, "[SISTEMA] Mensaje cifrado y enviado correctamente.\n")
    else:
        received_messages_text.insert(tk.END, "[SISTEMA] Error al cifrar y enviar el mensaje. Verifique las claves y vuelva a intentarlo.\n")

# Función para conectar al servidor
def connect_to_server():
    global client_socket
    
    if client_socket is None:
        if PRIVATE_KEY_FILE is None:
            tk.messagebox.showerror("Error", "Por favor selecciona un archivo de clave privada.")
            return

        if PUBLIC_KEY_FILE is None:
            tk.messagebox.showerror("Error", "Por favor selecciona un archivo de clave pública.")
            return

        password = password_entry.get()
        if not password:
            tk.messagebox.showerror("Error", "Por favor ingresa una contraseña.")
            return
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect(('127.0.0.1', 5555))
            threading.Thread(target=receive_message).start()  # Iniciar hilo para recibir mensajes
            messagebox.showinfo("Conexión establecida", "Conectado al servidor correctamente.")
            
            # Obtener la clave pública del emisor
            public_key = load_key_from_file(PUBLIC_KEY_FILE)
            
            # Imprimir la clave pública del emisor en su formato original
            print("Clave pública del emisor:", public_key.decode())
            
            # Codificar la clave pública del emisor en base64
            public_key_base64 = base64.b64encode(public_key).decode()
            
            # Imprimir la clave pública del emisor en formato base64
            print("Clave pública del emisor (base64):", public_key_base64)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")
        return



# Función para desconectarse del servidor
def disconnect_from_server():
    global client_socket
    
    if client_socket:
        client_socket.close()
        client_socket = None
        messagebox.showinfo("Desconexión", "Desconectado del servidor correctamente.")
    else:
        messagebox.showerror("Error", "No se ha establecido conexión con el servidor.")

# Configuración de la ventana principal
root = tk.Tk()
root.title("Cliente de Mensajería Segura")
root.geometry("800x600")

# Crear el frame principal
main_frame = ttk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True)

# Crear etiquetas para los archivos de claves
private_key_label = ttk.Label(main_frame, text="Private Key File:")
private_key_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

public_key_label = ttk.Label(main_frame, text="Public Key File:")
public_key_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

receiver_public_key_label = ttk.Label(main_frame, text="Receiver Public Key File:")
receiver_public_key_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)

# Crear botones para seleccionar archivos de claves
private_key_button = ttk.Button(main_frame, text="Seleccionar Clave Privada", command=select_private_key_file)
private_key_button.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

public_key_button = ttk.Button(main_frame, text="Seleccionar Clave Pública", command=select_public_key_file)
public_key_button.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

receiver_public_key_button = ttk.Button(main_frame, text="Seleccionar Clave Pública del Receptor", command=select_receiver_public_key_file)
receiver_public_key_button.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

private_key_reset_button = ttk.Button(main_frame, text="Resetear Selección", command=reset_private_key_selection, state=tk.DISABLED)
private_key_reset_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

public_key_reset_button = ttk.Button(main_frame, text="Resetear Selección", command=reset_public_key_selection, state=tk.DISABLED)
public_key_reset_button.grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)

receiver_public_key_reset_button = ttk.Button(main_frame, text="Resetear Selección", command=reset_receiver_public_key_selection, state=tk.DISABLED)
receiver_public_key_reset_button.grid(row=2, column=2, padx=5, pady=5, sticky=tk.W)

# Crear botones para realizar acciones
connect_button = ttk.Button(main_frame, text="Conectar al Servidor", command=connect_to_server)
connect_button.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)

# Agregar el botón para compartir la clave pública
share_public_key_button = ttk.Button(main_frame, text="Compartir llave pública", command=share_public_key)
share_public_key_button.grid(row=4, column=2, padx=5, pady=5, sticky=tk.W)

generate_keys_button = ttk.Button(main_frame, text="Generar y Guardar Claves", command=generate_and_save_keys)
generate_keys_button.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)

generate_secret_button = ttk.Button(main_frame, text="Cifrar y Enviar Secreto", command=encrypt_and_send_secret)
generate_secret_button.grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)

print_secret_button = ttk.Button(main_frame, text="Imprimir Secreto", command=print_secret)
print_secret_button.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)

# Entrada de contraseña
ttk.Label(main_frame, text="Contraseña:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
password_entry = ttk.Entry(main_frame, show="*")
password_entry.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)

# Entrada de mensaje
ttk.Label(main_frame, text="Mensaje:").grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)
message_entry = ttk.Entry(main_frame)
message_entry.grid(row=6, column=1, padx=5, pady=5, sticky=tk.W)

# Botón para enviar mensaje
send_message_button = ttk.Button(main_frame, text="Enviar Mensaje", command=encrypt_and_send_message)
send_message_button.grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)

# Texto para mensajes recibidos
received_messages_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=70, height=15)
received_messages_text.grid(row=8, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)

root.mainloop()
