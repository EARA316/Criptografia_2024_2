import socket
import hashlib
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext, filedialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2  # Importamos PBKDF2 para la clave simetrica


canal_host = None
canal_guest = None
conexion_host = None
conexion_guest = None
host_ip = None
PORT_HOST = 65432           # Puerto arbitrario no utilizado
PORT_GUEST = 65433          # Puerto arbitrario no utilizado

# ========================================================================================
# Funciones criptográficas
# ========================================================================================
# Función para generar una clave simétrica a partir de una contraseña
def generate_symmetric_key(password, salt=b'salt', iterations=100000):
    key = PBKDF2(password.encode(), salt, dkLen=32, count=100000, prf=lambda p, s: hashlib.sha256(p + s).digest())
    print("\nClave simétrica generada:", key)
    return key

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

# Función para generar un par de claves RSA (privada y pública)
def generate_asymetric_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    print('\nMi llave privada:',private_key.decode(),'\nMi llave publica:',public_key.decode())
    return private_key, public_key

# Función para cifrar un mensaje asimétricamente utilizando la clave pública
# El mensaje debe ser bytes, no string
def asymmetric_encrypt(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    cipher_text = cipher.encrypt(message)
    return cipher_text

# Función para descifrar un mensaje asimétricamente utilizando la clave privada
# El texto cifrado debe ser bytes, no string
def asymmetric_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

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
# ========================================================================================
# Funciones de UI
# ========================================================================================
# Función que inserta un mensaje de sistema
def system_msg(mensaje):
    msj = '[Sistema] '+mensaje+'\n'
    system_messages_text.insert(tk.END, msj)

# Función que solicita un texto al usuario y verifica que no sea una cadena vacía
def solicitud(titulo, mensaje):
    while True:
        texto_ingresado = simpledialog.askstring(titulo, mensaje)
        if texto_ingresado:
            break
    return texto_ingresado

def my_msg(mensaje):
    msj = '[Yo] '+mensaje+'\n'
    received_messages_text.insert(tk.END, msj)

def new_msg(mensaje):
    msj = '[Interlocutor] '+mensaje+'\n'
    received_messages_text.insert(tk.END, msj)

# ========================================================================================
# Funciones de conexión
# ========================================================================================
def obtenerIP():
    # Obtener el nombre de host de la máquina local
    hostname = socket.gethostname()
    # Obtener la dirección IP correspondiente al nombre de host
    direccion_ip = socket.gethostbyname(hostname)
    return direccion_ip


def recibir_msg():
    global conexion_host, conexion_guest, llave_privada, llaveP_interloc, clave_simetrica, isHost
    # Selecciona que canal escuchar, dependiendo del modo en que se
    # ejecuta el programa. Si es host, entonces debe escuchar el canal que creó
    # guest y viceversa.
    if isHost:
        conexion = conexion_guest
    else:
        conexion = conexion_host

    while True:
        try:
            if conexion:
                # Recibir datos
                crypt_msg_asym = conexion.recv(1024)
                if crypt_msg_asym == b'>>>FINALIZAR<<<':
                    cerrar_conexiones()
                    break
                print('\nCripto recibido: ',crypt_msg_asym)        
                nonce = conexion.recv(1024)
                print('\nNonce recibido: ',nonce)
                tag = conexion.recv(1024)
                print('\nTag recibido: ',tag)
                firma = conexion.recv(1024)
                print('\nFirma recibida: ',firma)

                system_msg('<= Mensaje recibido')

                # Desencriptado y verificación de firma
                crypt_msg_sym = asymmetric_decrypt(crypt_msg_asym, llave_privada)
                system_msg('Mensaje descifrado con método asimétrico')
                plaintext = symmetric_decrypt(crypt_msg_sym, nonce, tag, clave_simetrica)
                system_msg('Mensaje descifrado con método simétrico')
                firma_valida = verify_digital_signature(plaintext, firma, llaveP_interloc)

                if firma_valida:
                    system_msg('Firma válida. El mensaje es auténtico')
                    new_msg(plaintext)  
                else:
                    system_msg('Firma inválida. Se ha rechazado el mensaje')      
            else:
                print('conexion terminada')
                break
        except Exception as e:
            messagebox.showinfo("Atención", "Conexión terminada")  
            break 

def enviar_msg():
    global conexion_host, conexion_guest, clave_simetrica, llave_privada, llaveP_interloc, isHost
    # Selecciona que canal escuchar, dependiendo del modo en que se
    # ejecuta el programa. Si es host, entonces debe escuchar el canal que creó
    # guest y viceversa.
    if isHost:
        conexion = conexion_host
    else:
        conexion = conexion_guest

    # Descifrado y creación de firma
    mensaje = message_entry.get()
    my_msg(mensaje)
    crypt_msg_sym, nonce, tag = symmetric_encrypt(mensaje, clave_simetrica)
    system_msg('Mensaje cifrado con método simétrico')
    crypt_msg_asym = asymmetric_encrypt(crypt_msg_sym, llaveP_interloc)
    system_msg('Mensaje cifrado con método asimétrico')
    firma = generate_digital_signature(mensaje, llave_privada)
    system_msg('Firma generada')

    # Enviando los datos. Se incluyó un retraso entre cada envío para
    # evitar errores de comunicación.
    conexion.sendall(crypt_msg_asym)
    time.sleep(0.1)
    conexion.sendall(nonce)
    time.sleep(0.1)
    conexion.sendall(tag)
    time.sleep(0.1)
    conexion.sendall(firma)
    
    system_msg('=> Mensaje enviado')

    # Impresiones para debug
    print('\nCripto: ',crypt_msg_asym)
    print('\nNonce: ',nonce)
    print('\nTag: ',tag)
    print('\nFirma: ',firma)


# Función que contiene las ejecuciones iniciales para establecer la conexión
# desde el punto de vista de host.
def host_communication():
    global conexion_host, conexion_guest, canal_host, host_ip, PORT_HOST, PORT_GUEST, llave_publica, llaveP_interloc, clave_simetrica
    
    # Creación del canal host
    # Crear un objeto socket TCP/IP
    canal_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Vincular el socket al host y al puerto
    canal_host.bind((host_ip, PORT_HOST))    
    # Escuchar conexiones entrantes
    canal_host.listen()
    system_msg('Canal host iniciado. Esperando interlocutor...')
    # Aceptar conexiones entrantes
    conexion_host, addr = canal_host.accept()
    system_msg('Conexión host establecida con: '+ addr[0])

    # Creación del canal guest
    # Crear un objeto socket TCP/IP
    conexion_guest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Conectar al servidor
    conexion_guest.connect((addr[0], PORT_GUEST))
    system_msg('Conexión guest establecida con: '+ addr[0])

    # Enviar mi llave pública
    conexion_host.sendall(llave_publica)
    system_msg('Llave pública compartida con el interlocutor')
    # Recibir llave pública
    llaveP_interloc = conexion_guest.recv(1024)
    print('\n Llave publica recibida:',llaveP_interloc.decode())
    system_msg('Llave pública del interlocutor recibida')
    # Cifra la clave simetrica (asimetrico) con la llave publica del receptor
    secreto = asymmetric_encrypt(clave_simetrica, llaveP_interloc)
    # Envio del secreto al guest
    print('\nSecreto enviado:', secreto)
    system_msg('Llave simétrica cifrada con la llave pública del interlocutor (secreto)')
    conexion_host.sendall(secreto)
    system_msg('Secreto compartido con el interlocutor')

    # Confirmación de conexión verificada
    confirm = conexion_guest.recv(1024)
    if confirm == b"confirmado":
        # Inicio de la comunicación
        system_msg('Conexión verificada. Iniciando hilo de recepción de datos...')
        send_message_button.config(state=tk.NORMAL)
        end_communication_button.config(state=tk.NORMAL)
        recibir_thread = threading.Thread(target=recibir_msg)
        recibir_thread.start()
    else:
        system_msg('Conexión no verificada')
        cerrar_conexiones()

# Función que contiene las ejecuciones iniciales para establecer la conexión
# desde el punto de vista del invitado.
def guest_communication():
    global conexion_host, conexion_guest, canal_guest, host_ip, mi_ip, PORT_HOST, PORT_GUEST, llave_publica, llaveP_interloc, clave_simetrica, temp_password
    
    # Creación del canal host
    # Crear un objeto socket TCP/IP
    conexion_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Conectar al servidor
    conexion_host.connect((host_ip, PORT_HOST))
    system_msg('Conexión host establecida con: '+ host_ip)

    # Creación del canal guest
    # Crear un objeto socket TCP/IP
    canal_guest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Vincular el socket al host y al puerto
    canal_guest.bind((mi_ip, PORT_GUEST))    
    # Escuchar conexiones entrantes
    canal_guest.listen()
    system_msg('Canal guest iniciado. Esperando interlocutor...')
    # Aceptar conexiones entrantes
    conexion_guest, addr = canal_guest.accept()
    system_msg('Conexión guest establecida con: '+ addr[0])

    # Recibir llave publica del interlocutor
    llaveP_interloc = conexion_host.recv(1024)
    print('\n Llave publica recibida:',llaveP_interloc.decode())
    system_msg('Llave pública del interlocutor recibida')
    # Enviar mi llave pública
    conexion_guest.sendall(llave_publica)
    system_msg('Llave pública compartida con el interlocutor')
    # Recibir secreto
    secreto = conexion_host.recv(1024)
    print('\nSecreto recibido:', secreto)
    system_msg('Secreto recibido')
    # Descifrar secreto con mi llave privada
    clave_simetrica = asymmetric_decrypt(secreto, llave_privada)
    print('\n Clave simetrica obtenida:',clave_simetrica)

    # Verificar la conexión. La clave simetrica que se genera debe coincidir con
    # con la obtenida del secreto recibido.
    system_msg('Clave simetrica obtenida. Verificando conexión...')
    temp_simetrica = generate_symmetric_key(temp_password)
    if temp_simetrica == clave_simetrica:
        # Enviar la confirmación
        conexion_guest.sendall("confirmado".encode())
        # Iniciar conversación
        send_message_button.config(state=tk.NORMAL)
        end_communication_button.config(state=tk.NORMAL)
        system_msg('Conexión verificada. Iniciando hilo de recepción de datos...')
        recibir_thread = threading.Thread(target=recibir_msg)
        recibir_thread.start()
    else:
        system_msg('Conexión no verificada')
        cerrar_conexiones()

def cerrar_conexiones():
    global conexion_host, conexion_guest, canal_host, canal_guest, isHost
    send_message_button.config(state=tk.DISABLED)
    end_communication_button.config(state=tk.DISABLED)
    if isHost:
        conexion = conexion_host
    else:
        conexion = conexion_guest
    # Envía una bandera para finalizar la conexión en el interlocutor
    conexion.sendall(b'>>>FINALIZAR<<<')
    conexion.close()
    system_msg('Comunicación cancelada. debe reiniciar para crear una nueva conversación o unirse a una')

# ========================================================================================
# Ejecución principal
# ========================================================================================
password = ''
temp_password = ''
clave_simetrica = b''
llave_privada = b''
llave_publica = b''
llaveP_interloc= b'' # Llave publica del interlocutor
mi_ip = obtenerIP()

ventana = tk.Tk()
ventana.title("Cliente de Mensajería Segura")
ventana.resizable(0,0)

# Crear etiquetas para los archivos de claves
private_key_label = ttk.Label(ventana, text="Mi dirección IP es: "+mi_ip, font=("Arial",12))
private_key_label.grid(row=0, column=0, columnspan=3)

# Entrada de mensaje
ttk.Label(ventana, text="Mensaje:").grid(row=1, column=0, sticky=tk.W)
message_entry = ttk.Entry(ventana, width=40)
message_entry.grid(row=1, column=1)

# Botón para enviar mensaje
send_message_button = ttk.Button(ventana,text="Enviar Mensaje", state=tk.DISABLED, command=enviar_msg)
send_message_button.grid(row=1, column=2)

# Texto para mensajes recibidos
received_messages_text = scrolledtext.ScrolledText(ventana, wrap=tk.WORD, height=15)
received_messages_text.grid(row=2, column=0, columnspan=3)

# Entrada de mensajes de sistemas
ttk.Label(ventana, text="Mensajes del sistema:").grid(row=3, column=0, sticky=tk.W)

# Botón para terminar la conexión
end_communication_button = ttk.Button(ventana,text="Terminar comunicación", state=tk.DISABLED, command=cerrar_conexiones)
end_communication_button.grid(row=3, column=2)

# Texto para mensajes del sistema
system_messages_text = scrolledtext.ScrolledText(ventana, wrap=tk.WORD, height=10)
system_messages_text.grid(row=4, column=0, columnspan=3)


# Creando la conexión y generar las llaves dependiendo del modo de ejecución.
isHost = messagebox.askyesno("Modo de ejecución", "¿Deseas crear una nueva conversación?")
if isHost:
    password = solicitud('Ingresar contraseña', "Por favor, ingresa una contraseña para la conversación")
    clave_simetrica = generate_symmetric_key(password)
    system_msg('Clave simetrica generada')
    llave_privada, llave_publica = generate_asymetric_keys()
    system_msg('Llaves asimetricas generadas')
    host_ip = mi_ip       # localhost
    host_thread = threading.Thread(target=host_communication)
    host_thread.start()
else:
    host_ip = solicitud('Ingresar IP', "Por favor, ingresa la IP de la conversación a la que deseas unirte")
    time.sleep(1)
    temp_password = solicitud("Ingresa la contraseña", "Por favor, ingresa la contraseña de la conversación")
    llave_privada, llave_publica = generate_asymetric_keys()
    system_msg('Llaves asimetricas generadas')
    guest_thread = threading.Thread(target=guest_communication)
    guest_thread.start()


# Ejecutar el bucle de eventos
ventana.mainloop()