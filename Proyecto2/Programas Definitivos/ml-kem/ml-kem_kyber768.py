import oqs
from pprint import pprint
import time
import resource

# Obtención del uso de memoria antes de ejecutar el código
before_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

kemalg = "Kyber768"

with oqs.KeyEncapsulation(kemalg) as client:
    with oqs.KeyEncapsulation(kemalg) as server:
        print("Key encapsulation details:")
        pprint(client.details)

        # Inicia el contador de tiempo para la generación de claves
        start_time = time.time()
        public_key_client = client.generate_keypair()
        keygen_time = time.time() - start_time

        # Inicia el contador de tiempo para la encapsulación
        start_time = time.time()
        ciphertext, shared_secret_server = server.encap_secret(public_key_client)
        sign_time = time.time() - start_time

        # Inicia el contador de tiempo para la desencapsulación
        start_time = time.time()
        shared_secret_client = client.decap_secret(ciphertext)
        verify_time = time.time() - start_time

# Obtención del uso de memoria después de ejecutar el código
after_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

# Cálculo del uso de memoria
memory_usage = after_memory - before_memory

print("\nShared secretes coincide:", shared_secret_client == shared_secret_server)
print(f"Key generation time: {keygen_time} seconds")
print(f"Encapsulation time: {sign_time} seconds")
print(f"Decapsulation time: {verify_time} seconds")
print("Uso de memoria:", memory_usage, "bytes")
