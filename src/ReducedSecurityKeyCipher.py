import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from tinyec import registry
from tinyec.ec import Point


# todo: IMPORT PRIVATEKEY FROM FOLDER, ... AND THEN SAVE ALL THE OUTPUTS IN A FOLDER

AGGKEY_DIR = "../outputs/participant"




receiver_private_key = ec.generate_private_key(ec.SECP192R1())
receiver_public_key = receiver_private_key.public_key()
public_key_bytes = receiver_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint
)


def serialize_point(point):
    # Format as uncompressed point (04 + x + y)
    x_bytes = point.x.to_bytes(24, byteorder='big')  # 24 bytes for x secp192r1
    y_bytes = point.y.to_bytes(24, byteorder='big')  # 24 bytes for y secp192r1
    encoded_point = b'\x04' + x_bytes + y_bytes

    # Create public key from the encoded point using cryptography library to match the format used in ECIES script
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP192R1(),
        encoded_point
    )

    # Get compressed format (the one that ECIES script uses)
    compressed_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962, # X9.62 standard for elliptic curve public keys
        format=serialization.PublicFormat.CompressedPoint # Compressed point format (02 or 03 prefix)
    )


    #print("Compressed public key:", compressed_bytes.hex())
    return compressed_bytes

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

def agg_key_file_check():
    #Checks BTC aggregated key, does the number of hashes and calculates the secp192 public key [don't trust, verify ;)]
    file_path = os.path.join(AGGKEY_DIR, "aggregation_output.txt")

    # Open the file that the coordinator sent to us and save its contents
    if os.path.isfile(file_path) and file_path.endswith(".txt"):
        with open(file_path, "r") as f:
            agg_key_btc = f.readline().strip()
            number_of_hashes = f.readline().strip()
            secp192_pubkey = f.readline().strip()
    else:
        print(f"File does not exist or is not a valid .txt file.")

    # Checking if the encryption public key is correct
    agg_key_bytes = bytes.fromhex(agg_key_btc)
    hash_value = agg_key_bytes
    for _ in range(int(number_of_hashes)):
        hash_value = hashlib.sha256(hash_value).digest()
        #print(f"Hash value: {hash_value.hex()}")

    curve = registry.get_curve('secp192r1')
    # Get curve parameters (a, b and p) for secp192r1
    a = curve.a
    b = curve.b
    p = curve.field.p # secp192r1 prime field size
    x_bytes = hash_value[:24]
    x_candidate = int.from_bytes(x_bytes, 'big')
    x_candidate = x_candidate % p  # Apply modulo p to ensure x is within the prime field size
    right_side = (pow(x_candidate, 3, p) + (a * x_candidate) % p + b) % p  # Here we calculate the right side of the elliptic curve equation to find y²
    y = pow(right_side, (p + 1) // 4, p)
    try:
        # Create a point directly using the Point class from tinyec
        point = Point(curve, x_candidate, y)
        # print(f"Valid point found after {hash_attempts} hashes!")
        # print(f"Hash value: {hash_value.hex()}")
        # print(f"Point: x={point.x}, y={point.y}")
        # print(x_candidate)
        secp192r1_public_key = serialize_point(point)
        return secp192r1_public_key.hex() == secp192_pubkey
    except Exception as e:
        print(f"Error creating point: {e}")





def main():

    check = agg_key_file_check()
    #print(check)
    if check:
        print("Aggregated key file is valid, proceeding with encryption...")
    else:
        print("Aggregated key file is invalid, aborting encryption.")
        return




    message = b"Honeypot"

    # Cypher
    ephemeral_pub, iv, ct = ecies_encrypt(receiver_public_key, message)

    print(ephemeral_pub.hex())
    print(iv.hex())
    print(ct.hex())


if __name__ == "__main__":
    main()

