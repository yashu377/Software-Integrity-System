import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Read file
filename = "sample_file.txt"
with open(filename, "rb") as f:
    file_data = f.read()

# Generate SHA-256 hash
file_hash = hashlib.sha256(file_data).digest()

# Load private key
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# Sign hash
signature = private_key.sign(
    file_hash,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Save signature
with open("signature.sig", "wb") as sig_file:
    sig_file.write(signature)

print("✅ File signed successfully. Signature saved as 'signature.sig'")
