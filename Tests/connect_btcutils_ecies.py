import hashlib
from cryptography.hazmat.primitives.asymmetric import ec

# The objective here is to get a public key for secp192r1 from a secp256k1 hashed and truncated public key.
data_hex = "0309baa03c3c6103191e6f0f17684deb7dff75a3314ac75fa9dede79c7b7a279c1"

# Convert the hex string to bytes
data_bytes = bytes.fromhex(data_hex)

# First hash SHA-256
first_hash = hashlib.sha256(data_bytes).digest()

# Second hash SHA-256
double_hash = hashlib.sha256(first_hash).digest()

print("Double SHA-256:", double_hash.hex())  # Returns 32 bytes that need to be processed to generate a valid public key on secp192r1

# The idea is to truncate the 32 bytes to 24 bytes and then use the first 24 bytes as the x coordinate of the public key
