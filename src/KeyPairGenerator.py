import os
import uuid
import secrets
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey

KEYS_DIR = "../keys/participant"

def seedgen():
    print("Generating random 256 bits seed")
    # Use secrets to generate random bit sequence
    seed = secrets.randbits(256)
    return seed

def bitcoinkeygen(seed):
    # always remember to setup the network
    setup("testnet")
    # create a private key (from our generated bits)
    priv = PrivateKey(secret_exponent=seed)
    # compressed is the default
    print("\nPrivate key WIF:", priv.to_wif(compressed=True))
    # get the public key
    pub = priv.get_public_key()
    taprootpub = pub.get_taproot_address()
    print("\nTaproot address:", taprootpub.to_string())
    # create the directory if it doesn't exist
    os.makedirs(KEYS_DIR, exist_ok=True)
    # compressed is the default
    print("Public key:", pub.to_hex(compressed=True))
    # unique suffix for file names to avoid collisions when coordinator aggregates keys
    unique_suffix = str(uuid.uuid4())
    # save public and private keys to files
    pub_path = os.path.join(KEYS_DIR, f"public_key_{unique_suffix}_SHARE_THIS_FILE.txt")
    with open(pub_path, "w") as pub_file:
        pub_file.write(pub.to_hex(compressed=True))
    priv_path = os.path.join(KEYS_DIR, f"private_key_{unique_suffix}_DO_NOT_SHARE.txt")
    with open(priv_path, "w") as priv_file:
        priv_file.write(priv.to_wif(compressed=True))

def main():
    print("Welcome to BHQC protocol!\n")
    print("Generating your Key Pair and saving into .txt files...\n")
    # Generation of seed
    seed = seedgen()
    print(f"Your seed: {seed}")
    # Generation of Bitcoin private key (dg)
    bitcoinkeygen(seed)

if __name__ == "__main__":
    main()