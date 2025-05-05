import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

#This is an ECIES (Elliptic curve Integrated Encryption Scheme) example, probably the method that will be used to encrypt the privatekeys "dg" and to create the redeem script.


###############################################################################################################################################
###############################################################################################################################################
###############################################################################################################################################


# ----------- KEY GENERATION ---------- This part will be omitted because there's no need to generate a key,
# the public key Pp is generated adding all Pg's and hashing and truncating the result.
# No private key needed here, dp is unknown, and it's what the QC needs to solve in order to get all the funds.
receiver_private_key = ec.generate_private_key(ec.SECP192R1())
receiver_public_key = receiver_private_key.public_key()

# ----------- ECIES Encryption ----------
def ecies_encrypt(receiver_public_key, message: bytes):
    # 1. Ephemeral key: It's a one use key that gives forward secrecy (each message has a different key). The public key is the one that will be sent to the receiver of the message.
    ephemeral_private_key = ec.generate_private_key(ec.SECP192R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # 2. ECDH (Elliptic Curve Diffie-Hellman)
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), receiver_public_key)

    # 3. Symmetric key derivation
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'ecies',
    ).derive(shared_key)

    # 4. AES-CBC
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # 5. Serialize the ephemeral public key
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    return ephemeral_public_bytes, iv, ciphertext


# ----------- ECIES Decryption ----------
def ecies_decrypt(receiver_private_key, ephemeral_public_bytes, iv, ciphertext):
    # 1. Load ephemeral public key
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP192R1(),
        ephemeral_public_bytes
    )

    # 2. ECDH
    shared_key = receiver_private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # 3. Symmetric key derivation
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'ecies',
    ).derive(shared_key)

    # 4. AES-CBC
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # 5. Unpad
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


# ----------- Usage example ----------
message = b"Honeypot"

# Cypher
ephemeral_pub, iv, ct = ecies_encrypt(receiver_public_key, message)

# Decypher
missatge_desxifrat = ecies_decrypt(receiver_private_key, ephemeral_pub, iv, ct)
print("Decyphered message:", missatge_desxifrat.decode())
