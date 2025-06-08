import os
import hashlib
import re
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from tinyec import registry
from tinyec.ec import Point


AGGKEY_DIR = "../outputs/participant"
OUTPUTS_DIR = "../outputs/participant/ecies_output"
KEYS_DIR = "../outputs/participant/keys"



def get_private_key():
    for filename in os.listdir(KEYS_DIR):
        match = re.match(r"private_key_(.+?)_DO_NOT_SHARE\.txt", filename)
        if match:
            file_path = os.path.join(KEYS_DIR, filename)
            with open(file_path, "r") as f:
                privatekey_wif = f.read().strip()
                return privatekey_wif
    raise FileNotFoundError("No private key file with expected pattern found.")


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
        return secp192r1_public_key.hex() == secp192_pubkey, secp192_pubkey
    except Exception as e:
        print(f"Error creating point: {e}")
        return False

# Function to get the unique suffix from the public key file names
def get_unique_suffix():
    for filename in os.listdir(KEYS_DIR):
        match = re.match(r"public_key_(.+?)_SHARE_THIS_FILE\.txt", filename)
        if match:
            return match.group(1)
    raise FileNotFoundError("No public key file with expected pattern found.")

def get_public_key():
    for filename in os.listdir(KEYS_DIR):
        match = re.match(r"public_key_(.+?)_SHARE_THIS_FILE\.txt", filename)
        if match:
            file_path = os.path.join(KEYS_DIR, filename)
            with open(file_path, "r") as f:
                pubkey_hex = f.read().strip()
                return pubkey_hex
    raise FileNotFoundError("No public key file with expected pattern found.")

def main():

    check, receiver_public_key_hex = agg_key_file_check()

    if check:
        print("Aggregated key file is valid, proceeding with encryption...")
    else:
        print("Aggregated key file is invalid, aborting encryption.")
        return

    # Transform the public key from hex to bytes to the EC public key object
    receiver_public_key_bytes = bytes.fromhex(receiver_public_key_hex)
    receiver_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP192R1(),
        receiver_public_key_bytes
    )
    #print("Receiver's public key:", receiver_public_key_hex)

    private_wif = get_private_key()
    #print(private_wif)
    private_bytes = private_wif.encode('utf-8')
    #print("Message bytes:", private_bytes)

    # Cypher
    ephemeral_pub, iv, ct = ecies_encrypt(receiver_public_key, private_bytes)


    pubkey_participant = get_public_key()
    #print(pubkey_participant)

    #print(ct.hex())
    #print(iv.hex())
    #print(ephemeral_pub.hex())

    # Save the output to a file with a unique suffix, same as the public key file
    unique_suffix = get_unique_suffix()
    out_path = os.path.join(OUTPUTS_DIR, f"ecies_output_{unique_suffix}")
    with open(out_path, "w") as out_file:
        out_file.write(pubkey_participant + '\n')
        out_file.write(ct.hex() + '\n')
        out_file.write(iv.hex() + '\n')
        out_file.write(ephemeral_pub.hex())
    print("ECIES encryption completed successfully and saved to", out_path)




if __name__ == "__main__":
    main()

