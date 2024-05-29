import oqs
from pprint import pprint
import time

message = "This is the message to sign".encode()

print(message)

sigalg = "SPHINCS+-SHA2-256f-simple"

# Create a signer instance using the specified algorithm
signer = oqs.Signature(sigalg)

print("\nSignature details:")
pprint(signer.details)

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

print("\nValid signature?", is_valid)
print(f"Key generation time: {keygen_time} seconds")
print(f"Signing time: {sign_time} seconds")
print(f"Verification time: {verify_time} seconds")
#print(oqs.Signature.algorithms)
#print(oqs.get_enabled_sig_mechanisms())