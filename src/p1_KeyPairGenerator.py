import json
import os
import secrets
import math
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey

KEYS_DIR = "../outputs/participant/keys"
SETUP_DIR = "../setup.json"

def load_setup():
    # Load setup data from JSON file
    if not os.path.exists(SETUP_DIR):
        print(f"Setup file not found: {SETUP_DIR}")
        return None
    with open(SETUP_DIR, "r") as setup_file:
        setup_data = json.load(setup_file)
    
    return setup_data

def seed_bits_calc():
    setup_data = load_setup()
    if setup_data is None:
        return None
    num_participants = setup_data.get("num_participants")
    # Calculate bits of the seed (192-log2(n))
    bits_seed = 192 - math.log2(num_participants)
    return math.floor(bits_seed)

def seedgen():
    # Use secrets to generate random bit sequence
    seed = secrets.randbits(seed_bits_calc())
    return seed

def bitcoinkeygen(seed, network):
    # always remember to setup the network
    setup(network)

    # create a private key (from our generated bits)
    priv = PrivateKey(secret_exponent=seed)
    # compressed is the default

    # get the public key
    pub = priv.get_public_key()
   
    # create the directory if it doesn't exist
    os.makedirs(KEYS_DIR, exist_ok=True)


    # Extract x-coordinate from public key (uncompressed)
    pub_hex_uncompressed = pub.to_hex(compressed=False)
    pub_x_hex = pub_hex_uncompressed[2:66]
    pub_x_int = int(pub_x_hex, 16)

    # save public and private keys to files
    pub_path = os.path.join(KEYS_DIR, f"public_key_{pub_x_int}_{network}_SHARE_THIS_FILE.txt")
    with open(pub_path, "w") as pub_file:
        pub_file.write(pub.to_hex(compressed=True))
    priv_path = os.path.join(KEYS_DIR, f"private_key_{pub_x_int}_{network}_DO_NOT_SHARE.txt")
    with open(priv_path, "w") as priv_file:
        priv_file.write(priv.to_wif(compressed=True))

def main():
    print("Welcome to BHQC protocol!\n")
    # Initialize Bitcoin network
    while True:
        net_choice = input("Select network: (m)ainnet or (t)estnet?: ").strip().lower()
        if net_choice == "t":
            network = "testnet"
            break
        elif net_choice == "m":
            network = "mainnet"
            break
        else:
            print("Invalid input. Please enter 't' for testnet or 'm' for mainnet.")
    
    print("Generating your Key Pair and saving into .txt files...\n")
    # Generation of seed
    seed = seedgen()
    #print(f"Your seed: {seed}")
    # Generation of Bitcoin private key (dg)
    bitcoinkeygen(seed, network)
    print("Key Pair generated and saved successfully into ", KEYS_DIR)

if __name__ == "__main__":
    main()