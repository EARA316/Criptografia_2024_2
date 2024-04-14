"""                             
                    UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO
                            Facultad de Ingeniería
                        División de Ingeniería Eléctrica
                          Departamento de Computación
                                Semestre 2024-2
                                 Criptografia
                                Primer Proyecto

INTEGRANTES DEL EQUIPO:
- Aranda Quiroz Enrique
- Arreguin Portillo Diana Laura
- Cruz Zamora Joel David
- Rivas Arteaga Enrique Alan
"""

import socket  # Para la comunicación de red.
import hashlib  # Para generar resúmenes criptográficos de datos.
import time  # Para trabajar con el tiempo, como la medición de intervalos.
import threading  # Para ejecutar múltiples hilos de ejecución simultáneamente.
import tkinter as tk  # Para crear interfaces gráficas de usuario (GUI).
from tkinter import ttk, messagebox, simpledialog, scrolledtext, filedialog  # Componentes adicionales para GUI.
from tkinter import *
#ELEMENTOS NECESARIOS DE CRIPTOGRAFÍA
from Crypto.Cipher import AES, PKCS1_OAEP  # Para cifrar y descifrar datos.
from Crypto.PublicKey import RSA  # Para trabajar con claves públicas RSA.
from Crypto.Hash import SHA256  # Para calcular hash de mensajes y datos.
from Crypto.Signature import pkcs1_15  # Para firmar y verificar mensajes.
from Crypto.Protocol.KDF import PBKDF2  # Para derivar claves a partir de contraseñas.

# Variables globales para las conexiones
canal_host = None
canal_guest = None
conexion_host = None
conexion_guest = None
host_ip = None
PORT_HOST = 65432
PORT_GUEST = 65433

# Función para generar una clave simétrica a partir de una contraseña
def generate_symmetric_key(password, salt=b'salt', iterations=100000):
    key = PBKDF2(password.encode(), salt, dkLen=32, count=100000, prf=lambda p, s: hashlib.sha256(p + s).digest())
    print("\nClave simétrica generada:", key)
    return key

# Función para cifrar un mensaje usando AES
def symmetric_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, cipher.nonce, tag

# Función para descifrar un mensaje cifrado con AES
def symmetric_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Función para generar un par de claves RSA
def generate_asymetric_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    print('\nMi llave privada:',private_key.decode(),'\nMi llave publica:',public_key.decode())
    return private_key, public_key

# Función para cifrar un mensaje usando RSA
def asymmetric_encrypt(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    cipher_text = cipher.encrypt(message)
    return cipher_text

# Función para descifrar un mensaje cifrado con RSA
def asymmetric_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Función para generar un hash SHA256 de un mensaje
def generate_hash(message):
    hash_object = hashlib.sha256(message.encode())
    return hash_object.hexdigest()

# Función para generar una firma digital de un mensaje
def generate_digital_signature(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

# Función para verificar una firma digital de un mensaje
def verify_digital_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Función para mostrar mensajes del sistema en el cuadro de texto correspondiente
def system_msg(mensaje):
    msj = '[Sistema] '+mensaje+'\n'
    system_messages_text.insert(tk.END, msj)

# Función para solicitar al usuario algún tipo de entrada
def solicitud(titulo, mensaje):
    while True:
        texto_ingresado = simpledialog.askstring(titulo, mensaje)
        if texto_ingresado:
            break
    return texto_ingresado

# Función para mostrar los mensajes enviados por el usuario en el cuadro de texto correspondiente
def my_msg(mensaje):
    msj = '[Tú] '+mensaje+'\n'
    received_messages_text.insert(tk.END, msj)

# Función para mostrar los mensajes recibidos en el cuadro de texto correspondiente
def new_msg(mensaje):
    msj = '[Emisor] '+mensaje+'\n'
    received_messages_text.insert(tk.END, msj)

# Función para cambiar el color de la interfaz según si la conexión es válida o no
def cambiar_color_interfaz(valido):
    if valido:
        ventana.configure(bg='lightgreen')
    else:
        ventana.configure(bg='red')

# Función para obtener la dirección IP de la máquina local
def obtenerIP():
    hostname = socket.gethostname()
    direccion_ip = socket.gethostbyname(hostname)
    return direccion_ip

# Función para recibir mensajes
def recibir_msg():
    global conexion_host, conexion_guest, llave_privada, llaveP_interloc, clave_simetrica, isHost
    if isHost:
        conexion = conexion_guest
    else:
        conexion = conexion_host

    while True:
        try:
            if conexion:
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

# Función para enviar mensajes
def enviar_msg():
    global conexion_host, conexion_guest, clave_simetrica, llave_privada, llaveP_interloc, isHost
    if isHost:
        conexion = conexion_host
    else:
        conexion = conexion_guest

    mensaje = message_entry.get()
    my_msg(mensaje)
    crypt_msg_sym, nonce, tag = symmetric_encrypt(mensaje, clave_simetrica)
    system_msg('Mensaje cifrado con método simétrico')
    crypt_msg_asym = asymmetric_encrypt(crypt_msg_sym, llaveP_interloc)
    system_msg('Mensaje cifrado con método asimétrico')
    firma = generate_digital_signature(mensaje, llave_privada)
    system_msg('Firma generada')

    conexion.sendall(crypt_msg_asym)
    time.sleep(0.1)
    conexion.sendall(nonce)
    time.sleep(0.1)
    conexion.sendall(tag)
    time.sleep(0.1)
    conexion.sendall(firma)
    
    system_msg('=> Mensaje enviado')
    message_entry.delete(0, END)

    print('\nCripto: ',crypt_msg_asym)
    print('\nNonce: ',nonce)
    print('\nTag: ',tag)
    print('\nFirma: ',firma)

# Función para la comunicación del host
def host_communication():
    global conexion_host, conexion_guest, canal_host, host_ip, PORT_HOST, PORT_GUEST, llave_publica, llaveP_interloc, clave_simetrica

    canal_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    canal_host.bind((host_ip, PORT_HOST))
    canal_host.listen()
    system_msg('Canal host iniciado. Esperando interlocutor...')

    conexion_host, addr = canal_host.accept()
    system_msg('Conexión host establecida con: '+ addr[0])

    conexion_guest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conexion_guest.connect((addr[0], PORT_GUEST))
    system_msg('Conexión guest establecida con: '+ addr[0])

    conexion_host.sendall(llave_publica)
    system_msg('Llave pública compartida con el interlocutor')
    llaveP_interloc = conexion_guest.recv(1024)
    print('\n Llave publica recibida:',llaveP_interloc.decode())
    system_msg('Llave pública del interlocutor recibida')

    secreto = asymmetric_encrypt(clave_simetrica, llaveP_interloc)
    print('\nSecreto enviado:', secreto)
    system_msg('Llave simétrica cifrada con la llave pública del interlocutor (secreto)')
    conexion_host.sendall(secreto)
    system_msg('Secreto compartido con el interlocutor')

    confirm = conexion_guest.recv(1024)
    if confirm == b"confirmado":
        system_msg('Conexión verificada. Iniciando hilo de recepción de datos...')
        send_message_button.config(state=tk.NORMAL)
        end_communication_button.config(state=tk.NORMAL)
        cambiar_color_interfaz(True)
        recibir_thread = threading.Thread(target=recibir_msg)
        recibir_thread.start()
    else:
        cambiar_color_interfaz(False)
        system_msg('Conexión no verificada')
        cerrar_conexiones()

# Función para la comunicación del invitado
def guest_communication():
    global conexion_host, conexion_guest, canal_guest, host_ip, mi_ip, PORT_HOST, PORT_GUEST, llave_publica, llaveP_interloc, clave_simetrica, temp_password

    conexion_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conexion_host.connect((host_ip, PORT_HOST))
    system_msg('Conexión host establecida con: '+ host_ip)

    canal_guest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    canal_guest.bind((mi_ip, PORT_GUEST))
    canal_guest.listen()
    system_msg('Canal guest iniciado. Esperando interlocutor...')

    conexion_guest, addr = canal_guest.accept()
    system_msg('Conexión guest establecida con: '+ addr[0])

    llaveP_interloc = conexion_host.recv(1024)
    print('\n Llave publica recibida:',llaveP_interloc.decode())
    system_msg('Llave pública del interlocutor recibida')

    conexion_guest.sendall(llave_publica)
    system_msg('Llave pública compartida con el interlocutor')

    secreto = conexion_host.recv(1024)
    print('\nSecreto recibido:', secreto)
    system_msg('Secreto recibido')

    clave_simetrica = asymmetric_decrypt(secreto, llave_privada)
    print('\n Clave simetrica obtenida:',clave_simetrica)

    system_msg('Clave simetrica obtenida. Verificando conexión...')
    temp_simetrica = generate_symmetric_key(temp_password)
    if temp_simetrica == clave_simetrica:
        conexion_guest.sendall("confirmado".encode())
        send_message_button.config(state=tk.NORMAL)
        end_communication_button.config(state=tk.NORMAL)
        cambiar_color_interfaz(True)
        system_msg('Conexión verificada. Iniciando hilo de recepción de datos...')
        recibir_thread = threading.Thread(target=recibir_msg)
        recibir_thread.start()
    else:
        cambiar_color_interfaz(False)
        system_msg('Conexión no verificada')
        cerrar_conexiones()

# Función para cerrar las conexiones
def cerrar_conexiones():
    global conexion_host, conexion_guest, canal_host, canal_guest, isHost
    send_message_button.config(state=tk.DISABLED)
    end_communication_button.config(state=tk.DISABLED)
    if isHost:
        conexion = conexion_host
    else:
        conexion = conexion_guest
    conexion.sendall(b'>>>FINALIZAR<<<')
    conexion.close()
    system_msg('Comunicación cancelada. debe reiniciar para crear una nueva conversación o unirse a una')

# Lógica principal
password = ''
temp_password = ''
clave_simetrica = b''
llave_privada = b''
llave_publica = b''
llaveP_interloc= b''
mi_ip = obtenerIP()

# Configuración de la ventana de la aplicación
ventana = tk.Tk()
ventana.title("Proyecto 01: Criptografía   Semestre 2024-2  FACULTAD DE INGENIERÍA UNAM")
ventana.resizable(0,0)

# Etiqueta para mostrar la dirección IP
private_key_label = ttk.Label(ventana, text="Mi dirección IP es: "+mi_ip, font=("Arial",12))
private_key_label.grid(row=0, column=0, columnspan=3)

# Elementos de la interfaz de usuario
ttk.Label(ventana, text="Mensaje:").grid(row=1, column=0, sticky=tk.W)
message_entry = ttk.Entry(ventana, width=40)
message_entry.grid(row=1, column=1)

send_message_button = ttk.Button(ventana,text="Enviar Mensaje", state=tk.DISABLED, command=enviar_msg)
send_message_button.grid(row=1, column=2)

received_messages_text = scrolledtext.ScrolledText(ventana, wrap=tk.WORD, height=15)
received_messages_text.grid(row=2, column=0, columnspan=3)

ttk.Label(ventana, text="Mensajes del sistema:").grid(row=3, column=0, sticky=tk.W)

end_communication_button = ttk.Button(ventana,text="Terminar comunicación", state=tk.DISABLED, command=cerrar_conexiones)
end_communication_button.grid(row=3, column=2)

system_messages_text = scrolledtext.ScrolledText(ventana, wrap=tk.WORD, height=10)
system_messages_text.grid(row=4, column=0, columnspan=3)

# Determinar si el usuario desea ser el anfitrión o el invitado
isHost = messagebox.askyesno("Modo de ejecución", "¿Deseas crear una nueva conversación?")
if isHost:
    password = solicitud('Ingresar contraseña', "Por favor, ingresa una contraseña para la conversación")
    clave_simetrica = generate_symmetric_key(password)
    system_msg('Clave simetrica generada')
    llave_privada, llave_publica = generate_asymetric_keys()
    system_msg('Llaves asimetricas generadas')
    host_ip = mi_ip
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

ventana.mainloop()
