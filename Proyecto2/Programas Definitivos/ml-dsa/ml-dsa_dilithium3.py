import oqs
import time
import resource

# Obtención del uso de memoria antes de ejecutar el código
before_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

message = "This is the message to sign".encode()

print("Message to sign:", message)

sigalg = "Dilithium3"

# Create a signer instance using the specified algorithm
signer = oqs.Signature(sigalg)

# Key generation
start_time = time.time()
signer_public_key = signer.generate_keypair()
keygen_time = time.time() - start_time

# Signing
start_time = time.time()
signature = signer.sign(message)
sign_time = time.time() - start_time

# Verification
verifier = oqs.Signature(sigalg)
start_time = time.time()
is_valid = verifier.verify(message, signature, signer_public_key)
verify_time = time.time() - start_time

# Obtención del uso de memoria después de ejecutar el código
after_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

# Cálculo del uso de memoria
memory_usage = after_memory - before_memory

print("\nSignature algorithm:", sigalg)
print("Signature details:")
print("Public key length:", signer.details["length_public_key"])
print("Secret key length:", signer.details["length_secret_key"])
print("Signature length:", signer.details["length_signature"])
print("Is EUF-CMA secure?", signer.details["is_euf_cma"])

print("\nKey generation time:", keygen_time, "seconds")
print("Signing time:", sign_time, "seconds")
print("Verification time:", verify_time, "seconds")

print("\nValid signature?", is_valid)
print("Uso de memoria:", memory_usage, "bytes")
