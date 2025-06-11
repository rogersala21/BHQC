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
public_key_bytes = receiver_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint
)
print("Public key:", public_key_bytes.hex()) #Compressed pubkey that is 25 bytes long


with open('../outputs/stealer/private_key.txt', 'wb') as f:
    pem = receiver_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    f.write(pem)


# LOADED KEY FROM CONNNECT BTCUTILS ECIES
#compressed_public_key_hex = "02fbff07a5468c10147f2a20d1a9ecf80fe3a30c1bdf7641b0"
#compressed_public_key_bytes = bytes.fromhex(compressed_public_key_hex)

# Create public key object from the bytes
#receiver_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
#    ec.SECP192R1(),
#    compressed_public_key_bytes
#)



# ----------- ECIES Encryption (Sender) ----------
def ecies_encrypt(receiver_public_key, message: bytes):
    # 1. Ephemeral key: It's a one use key that gives forward secrecy (each message has a different key). The public key is the one that will be sent to the receiver of the message.
    ephemeral_private_key = ec.generate_private_key(ec.SECP192R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # 2. ECDH (Elliptic Curve Diffie-Hellman) method to generate a shared key between two participants (finding a shared point in the EC). [privA * pubB = privA * (privB * G) = privB * (privA * G) = privB * pubA]
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), receiver_public_key) #It's a large binary string of bytes.

    # 3. Symmetric key derivation: (needed to process "shared_key" to make it suitable for AES-128 = 16 bytes) Produces a clean and uniform key.
    derived_key = HKDF(                 #HMAC-based Key Derivation Function (extract and expand secret information in a symmetric secure key with a fixed size). This is the constructor.
        algorithm=hashes.SHA256(),      #Using sha256 algorithm.
        length=16,                      #Choose the length of symmetric key (16 bytes = 128 bits).
        salt=None,                      #Optional (helps to protect from reused key attacks).
        info=b'ecies',                  #Optional (just to denote the purpose of the key).
    ).derive(shared_key)                #This is what actually does all the calculations.

    # 4. AES-CBC
    iv = os.urandom(16)                                             #This is the Initialization Vector (needed for the CBC (cypher block chaining that processes the message in 16 bits blocks)) 16 random bytes are generated, this value does not have to be secret, but it has to be unique for each cypher.
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))     #Then a cypher object is created (defining that will use AES, CBC mode (that cyphers each block depending on the previous), using the "derived_key" obtained before.
    encryptor = cipher.encryptor()                                  #The cypher object is prepared to encrypt, starts the algorithm with all the parameters.

    padder = sym_padding.PKCS7(128).padder()                            #AES needs that the message is multiple of 16 bytes, if not, padding is needed. Uses the PKCS7 standard, 128 indicates that the blocks will be of 128 bits = 16 bytes. Creates an object to add padding.
    padded_data = padder.update(message) + padder.finalize()            #The padder object adds the padding bytes needed to the message, PKCS7 adds N bytes with the value N.
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()   #The padded message is cyphered.

    # 5. Serialize the ephemeral public key: Convert the ephemeral pubkey in a standard format.
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(     #Serialize into byte format.
        encoding=serialization.Encoding.X962,                       #X962 is the standard for EC.
        format=serialization.PublicFormat.UncompressedPoint         #Serialize as a point with both coordinates (x,y).
    )

    return ephemeral_public_bytes, iv, ciphertext


# ----------- ECIES Decryption (Receiver)----------
def ecies_decrypt(receiver_private_key, ephemeral_public_bytes, iv, ciphertext):
    # 1. Load ephemeral public key
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(        #Reverts the ephemeral pubkey serialization done on the Encryption.
        ec.SECP192R1(),                                                         #Indicate the EC used.
        ephemeral_public_bytes                                                  #The key that we want to deserialize.
    )

    # 2. ECDH (Elliptic Curve Diffie-Hellman) method to generate a shared key between two participants (finding a shared point in the EC), now we have the shared key between both parts.
    shared_key = receiver_private_key.exchange(ec.ECDH(), ephemeral_public_key) #It's a large binary string of bytes.

    # 3. Symmetric key derivation: exactly the same as in Encryption.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'ecies',
    ).derive(shared_key)

    # 4. AES-CBC
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))              #A cypher object is created (defining that will use AES, CBC mode (that cyphers each block depending on the previous), using the "derived_key" obtained before.
    decryptor = cipher.decryptor()                                           #The cypher object is prepared to decrypt, starts the algorithm with all the parameters.
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()   #The cyphered message is now deciphered.

    # 5. Unpad: We needed to use padding to encrypt, so after decrypting, we need to unpad to get the original message.
    unpadder = sym_padding.PKCS7(128).unpadder()                            #Creates an object to unpad.
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()     #The unpadder object removes the padding bytes of the message, checks the value of the last byte to know how much needs to unpad.
    return plaintext


# ----------- Usage example ----------
message = b"Honeypot"       #Message as a byte string

# Cypher
ephemeral_pub, iv, ct = ecies_encrypt(receiver_public_key, message)

#print(ct.hex())
print(ephemeral_pub.hex())
print(iv.hex())
print(ct.hex())

ephemeral_pub_hex = ephemeral_pub.hex()
iv_hex = iv.hex()
ephemeral_bytes = bytes.fromhex(ephemeral_pub_hex)
iv_bytes = bytes.fromhex(iv_hex)

# Save ciphertext as hex
ct_hex = ct.hex()

# Later, load and convert back to bytes
ct_bytes = bytes.fromhex(ct_hex)

# Decypher
deciphered_message = ecies_decrypt(receiver_private_key, ephemeral_bytes, iv_bytes, ct_bytes)
print("Deciphered message:", deciphered_message.decode())
