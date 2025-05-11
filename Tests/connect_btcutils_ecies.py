import hashlib
from cryptography.hazmat.primitives.asymmetric import ec

# The objective here is to get a public key for secp192r1 from a secp256k1 hashed and truncated public key.
data_hex = "033ec18307abf6332951a7b424ca80d00b6f15b442a81042096313a99b8b158feb"

# Convert the hex string to bytes
data_bytes = bytes.fromhex(data_hex)

# First hash SHA-256
first_hash = hashlib.sha256(data_bytes).digest()

# Second hash SHA-256
double_hash = hashlib.sha256(first_hash).digest()

print("Double SHA-256:", double_hash.hex())  # Returns 32 bytes that need to be processed to generate a valid public key on secp192r1

