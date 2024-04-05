import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def generate_symmetric_key(password, salt=b'salt', iterations=100000):
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return key[:32]  # AES-256 key

def symmetric_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, cipher.nonce, tag

def symmetric_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

def asymmetric_encrypt(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    cipher_text = cipher.encrypt(message.encode())
    return cipher_text

def asymmetric_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

def generate_hash(message):
    hash_object = hashlib.sha256(message.encode())
    return hash_object.hexdigest()

def generate_digital_signature(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_digital_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Example usage:

# 1. User Interface
password = input("Enter your password: ")

# 2. Key Generation
private_key, public_key = generate_keys()
symmetric_key = generate_symmetric_key(password)

# 3. Encryption
message = "This is a secret message."
encrypted_message, nonce, tag = symmetric_encrypt(message, symmetric_key)
symmetric_key_str = base64.b64encode(symmetric_key).decode()
encrypted_symmetric_key = asymmetric_encrypt(symmetric_key_str, public_key)

# 4. Hashing
message_digest = generate_hash(message)

# 5. Digital Signature
signature = generate_digital_signature(message, private_key)

# 6. Secure Storage
# You can securely store private_key using appropriate cryptographic techniques.

# Demonstration of decryption, verification, etc.
decrypted_symmetric_key_str = asymmetric_decrypt(encrypted_symmetric_key, private_key)
decrypted_symmetric_key = base64.b64decode(decrypted_symmetric_key_str)
decrypted_message = symmetric_decrypt(encrypted_message, nonce, tag, decrypted_symmetric_key)
signature_verified = verify_digital_signature(message, signature, public_key)

print("Original Message:", message)
print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message)
print("Message Digest:", message_digest)
print("Digital Signature Verified:", signature_verified)
