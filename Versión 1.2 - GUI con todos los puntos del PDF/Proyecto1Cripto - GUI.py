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
from Crypto.Protocol.KDF import PBKDF2  # Importamos PBKDF2
import base64
import threading

main_frame = None  # Declaramos main_frame como una variable global
PRIVATE_KEY_FILE = None
PUBLIC_KEY_FILE = None
client_socket = None

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

# Función para cargar una clave desde un archivo
def load_key_from_file(filename):
    if filename is None:
        return None
    try:
        with open(filename, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print("Archivo no encontrado:", filename)
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

# Función para recibir mensajes del servidor
def receive_message():
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
                print("Decrypted Received Message:", decrypted_message)
                received_messages_text.insert(tk.END, f"Server: {decrypted_message}\n")
            else:
                print("Digital Signature Verification Failed for Received Message")

# Función para recibir mensajes desde el servidor
def receive_message_from_server():
    global client_socket
    
    if client_socket is None:
        messagebox.showerror("Error", "No se ha establecido conexión con el servidor.")
        return
    
    data = client_socket.recv(1024)
    return data.decode()

# Función para manejar la conexión con el cliente
def handle_client():
    threading.Thread(target=receive_message).start()

# Función para seleccionar un archivo de clave privada
def select_private_key_file():
    global PRIVATE_KEY_FILE
    filename = filedialog.askopenfilename()
    if filename:
        PRIVATE_KEY_FILE = filename
        current_text = private_key_label.cget('text')
        if not current_text.endswith(":"):
            current_text += " "
        private_key_label.config(text=current_text + " " + PRIVATE_KEY_FILE)

# Función para seleccionar un archivo de clave pública
def select_public_key_file():
    global PUBLIC_KEY_FILE
    filename = filedialog.askopenfilename()
    if filename:
        PUBLIC_KEY_FILE = filename
        current_text = public_key_label.cget('text')
        if not current_text.endswith(":"):
            current_text += " "
        public_key_label.config(text=current_text + " " + PUBLIC_KEY_FILE)

# Función para cifrar y enviar un mensaje al servidor
def encrypt_and_send_message():
    global client_socket
    
    if client_socket is None:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect(('127.0.0.1', 5555))
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

    print("Original Message:", message)
    print("Encrypted Message:", encrypted_message)
    print("Decrypted Message:", decrypted_message)
    print("Message Digest:", message_digest)
    print("Digital Signature Verified:", signature_verified)

    send_message(json.dumps({
        'message': base64.b64encode(encrypted_message).decode(),
        'signature': base64.b64encode(signature).decode()
    }))

    if signature_verified:
        received_messages_text.insert(tk.END, "[SISTEMA] Mensaje cifrado y enviado correctamente.\n")
    else:
        received_messages_text.insert(tk.END, "[SISTEMA] Error al cifrar y enviar el mensaje. Verifique las claves y vuelva a intentarlo.\n")

# Función para conectarse al servidor
def connect_to_server():
    global client_socket
    
    if client_socket is None:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect(('127.0.0.1', 5555))
            messagebox.showinfo("Conexión establecida", "Conectado al servidor correctamente.")
            threading.Thread(target=receive_message).start()  # Iniciar hilo para recibir mensajes
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

# GUI setup
root = tk.Tk()
root.title("Proyecto 01: Criptografía")

main_frame = ttk.Frame(root, padding="20")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

generate_keys_button = ttk.Button(main_frame, text="Generate Keys", command=generate_and_save_keys)
generate_keys_button.grid(row=0, column=0, columnspan=2, pady=10)

private_key_label = ttk.Label(main_frame, text="Private Key File:")
private_key_label.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)

private_key_button = ttk.Button(main_frame, text="Select Private Key File", command=select_private_key_file)
private_key_button.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

public_key_label = ttk.Label(main_frame, text="Public Key File:")
public_key_label.grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)

public_key_button = ttk.Button(main_frame, text="Select Public Key File", command=select_public_key_file)
public_key_button.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

password_label = ttk.Label(main_frame, text="Enter Password:")
password_label.grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)

password_entry = ttk.Entry(main_frame, show="*")
password_entry.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)

message_label = ttk.Label(main_frame, text="Enter Message:")
message_label.grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)

message_entry = ttk.Entry(main_frame)
message_entry.grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)

send_button = ttk.Button(main_frame, text="Encrypt and Send Message", command=encrypt_and_send_message)
send_button.grid(row=5, column=0, columnspan=2, pady=10)

# Agregar el botón de conexión en la interfaz gráfica
connect_button = ttk.Button(main_frame, text="Connect to Server", command=connect_to_server)
connect_button.grid(row=6, column=0, columnspan=1, pady=10, padx=(10, 5))

# Agregar el botón de desconexión en la interfaz gráfica
disconnect_button = ttk.Button(main_frame, text="Disconnect from Server", command=disconnect_from_server)
disconnect_button.grid(row=6, column=1, columnspan=1, pady=10, padx=(5,))

received_messages_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD)
received_messages_text.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()
