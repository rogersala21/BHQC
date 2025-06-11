import c2_PublicKeyAggregator as pub_agg
import c4_HoneypotCommitment as honeypot_commitment
import sys
import glob
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from coincurve import PrivateKey
from bitcoinutils.keys import PrivateKey as BitcoinPrivateKey
from bitcoinutils.setup import setup
from bitcoinutils.utils import tweak_taproot_privkey
from modules.descriptor import descsum_create

def check_data_correctness(introduced_taproot_address):
    secp192r1_pub = pub_agg.main()

    network, calculated_taproot_address, tweak_int = honeypot_commitment.main(False)
    if introduced_taproot_address == calculated_taproot_address:
        print("Data is correct. The introduced taproot address matches the calculated one, proceeding with the next steps...\n")
        return secp192r1_pub, tweak_int, network, calculated_taproot_address
    else:
        print("Data is incorrect. The introduced taproot address does not match the calculated one.")
        print(f"Introduced address: {introduced_taproot_address}")
        print(f"Calculated address: {calculated_taproot_address}")
        print("Please check your data and try again...")
        sys.exit(0)

def get_secp192r1_private_key():
    txt_files = glob.glob('../outputs/stealer/*.txt')
    for filename in txt_files:
        with open(filename, 'r') as f:
            content = f.read()
            if content.startswith('-----BEGIN EC PRIVATE KEY-----'):
                print(f"Private key found in {filename}.")
                return content
    print("No EC private key found in ../outputs/stealer/.")
    sys.exit(0)

def check_private_key(secp192r1_privatekey_raw, secp192r1_pub):
    secp192r1_processed = serialization.load_pem_private_key(
        secp192r1_privatekey_raw.encode(),
        password=None,
    )

    receiver_public_key = secp192r1_processed.public_key()
    public_key_bytes = receiver_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

    check = (public_key_bytes.hex() == secp192r1_pub)
    if check:
        print("The secp192r1 private key corresponds to the public key.\n")
        return secp192r1_processed
    else:
        print("The secp192r1 private key does not correspond to the public key.")
        print(f"Private key public key: {public_key_bytes.hex()}")
        print(f"Expected public key: {secp192r1_pub}")
        print("Please check your private key and try again...")
        sys.exit(0)

def ecies_pre_decrypt(checked_private):
    txt_files = glob.glob('../outputs/coordinator/honeypot_commitment/*')
    decrypted_results = []
    for filename in txt_files:
        with open(filename, 'r') as f:
            lines = f.read().splitlines()

            cyphertext_bytes = bytes.fromhex(lines[1])
            iv_bytes = bytes.fromhex(lines[2])
            ephemeral_pub_bytes = bytes.fromhex(lines[3])
            bitcoin_private = ecies_decrypt(checked_private, ephemeral_pub_bytes, iv_bytes, cyphertext_bytes)
            decrypted_results.append(bitcoin_private.decode())
    return decrypted_results

def wif_aggregation(list_decrypted_privates):

    # Convert WIF to coincurve.PrivateKey
    coincurve_privs = []
    for wif in list_decrypted_privates:
        btc_priv = BitcoinPrivateKey(wif)
        priv_bytes = btc_priv.to_bytes()
        cc_priv = PrivateKey(priv_bytes)
        coincurve_privs.append(cc_priv)


    # Aggregate the private keys
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    x_sum = sum(int.from_bytes(priv.secret, 'big') for priv in coincurve_privs) % n
    agg_secret = PrivateKey(x_sum.to_bytes(32, 'big'))

    # Convert the aggregated private key to Bitcoin WIF format
    agg_secret_bytes = agg_secret.secret  # 32 bytes
    btc_priv = BitcoinPrivateKey.from_bytes(agg_secret_bytes)
    wif = btc_priv.to_wif()

    return wif

def tweak_wif_key(wif_before_tweak, tweak_int):
    priv = BitcoinPrivateKey(wif_before_tweak)
    priv_key_bytes = priv.to_bytes()
    tweaked_privkey_bytes = tweak_taproot_privkey(priv_key_bytes, tweak_int)
    tweaked_privkey = BitcoinPrivateKey.from_bytes(tweaked_privkey_bytes)

    return tweaked_privkey.to_wif()


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

def create_wallet_descriptor(honeypot_wif):
    descriptor = f"tr({honeypot_wif})"
    descriptor_with_checksum = descsum_create(descriptor)
    print("Creating wallet descriptor ready to import into Bitcoin Core... \n")
    lines = [
        'createwallet "BHQC"',
        '',
        'importdescriptors \'[{',
        f'  "desc": "{descriptor_with_checksum}",',
        '  "timestamp": 0,',
        '  "label": "Honeypot"',
        '}]\''
    ]

    with open('../outputs/stealer/bitcoin_core_import.txt', 'w') as f:
        for line in lines:
            f.write(line + '\n')

    print("Wallet descriptor created and saved in ../outputs/stealer/bitcoin_core_import.txt")

    print("Content of the file:")
    with open('../outputs/stealer/bitcoin_core_import.txt', 'r') as f:
        content = f.read()
        print(content)


def main():
    print("Starting to check data correctness...")
    while True:
        data_correctness_response = input(
            "Make sure you have the public keys of all participants in the folder ../outputs/coordinator/key_agg_input. "
            "And the ECIES outputs in ../outputs/coordinator/honeypot_commitment. Do you want to continue? (yes/no): "
        )
        if data_correctness_response.lower() == "yes":
            introduced_taproot_address = input("Please introduce the honeypot taproot address: ")
            secp192r1_pub, tweak_int, network, calculated_taproot_address = check_data_correctness(introduced_taproot_address)
            setup(network)
            break
        elif data_correctness_response.lower() == "no":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

    print("Strarting to decrypt ECIES outputs...")
    while True:
        secp192r1_private_response = input(f"Make sure you have the secp192r1 private key corresponding to public key {secp192r1_pub} in PEM format (SEC1, unencrypted) into ../outputs/stealer/*.txt Do you want to continue? (yes/no): ")
        if secp192r1_private_response.lower() == "yes":
            secp192r1_privatekey_raw = get_secp192r1_private_key()
            break
        elif secp192r1_private_response.lower() == "no":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

    # AGGREGATION OF ALL DECRYPTED KEYS
    print("Checking if the secp192r1 private key corresponds to the public key...")
    checked_private = check_private_key(secp192r1_privatekey_raw, secp192r1_pub)
    list_decrypted_privates = ecies_pre_decrypt(checked_private)
    wif_before_tweak = wif_aggregation(list_decrypted_privates)

    # GENERATE THE TWEAKED PRIVATE KEY (HONEYPOT PRIVATE KEY)
    honeypot_wif = tweak_wif_key(wif_before_tweak, tweak_int)

    priv = BitcoinPrivateKey.from_wif(honeypot_wif)

    # get the public key
    pub = priv.get_public_key()

    taprootpub = pub.get_taproot_address()

    if taprootpub.to_string() == calculated_taproot_address:
        print("The tweaked WIF matches the calculated taproot address!!! \n")
    else:
        print("The tweaked WIF does not match the calculated taproot address, some participant encrypted something that is not a privatekey.")
        print(f"Calculated address: {calculated_taproot_address}")
        print(f"Tweaked WIF address: {taprootpub.to_string()}")
        sys.exit(0)

    # CONVERT THE HONEYPOT PRIVATE KEY TO WIF AND THEN USE DESCPIPTOR.PY TO GENERATE THE DESCRIPTOR READY TO IMPORT INTO BITCOIN CORE AND ALSO SAVE IT IN A FILE
    create_wallet_descriptor(honeypot_wif)









if __name__ == "__main__":
    main()