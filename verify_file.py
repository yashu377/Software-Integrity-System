import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

filename = "sample_file.txt"

# Read file
with open(filename, "rb") as f:
    file_data = f.read()

# Recalculate hash
file_hash = hashlib.sha256(file_data).digest()

# Load public key
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# Load signature
with open("signature.sig", "rb") as sig_file:
    signature = sig_file.read()

# Verify signature
try:
    public_key.verify(
        signature,
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Verification successful — file integrity is intact.")
except InvalidSignature:
    print("❌ Verification failed — file may have been modified or tampered with.")
