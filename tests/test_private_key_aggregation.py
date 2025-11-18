from importlib.resources import files
import os
from pdb import main
import re
from cryptography.hazmat.primitives.asymmetric import ec
from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup

KEYS_DIR = "../outputs/stealer"

def wif_to_int(wif):
    priv = PrivateKey(wif)
    priv_bytes = priv.to_bytes()
    di = int.from_bytes(priv_bytes, 'big')
    return di

def load_private_keys(keys_dir):
    # We iterate through all private key files in the specified directory and create a list of PrivateKey objects.
    priv_key_list = []
    for filename in os.listdir(keys_dir):
        file_path = os.path.join(keys_dir, filename)
        if os.path.isfile(file_path) and filename.startswith("private_key_") and filename.endswith(".txt"):
            # Extract network from filename
            match = re.search(r'_(mainnet|testnet)_DO_NOT_SHARE\.txt$', filename)
            if not match:
                raise ValueError(f"Network not found in private key filename: {filename}")
            network = match.group(1)
            setup(network)
            with open(file_path, "r") as f:
                wif_key = f.read().strip()
                priv_key_int = wif_to_int(wif_key)
                priv_key_list.append(priv_key_int)
    return priv_key_list

def aggregate_private_keys(priv_key_ints):
    # Combine the private keys into a single aggregated private key
    b_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    w_order = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
    agg_priv_int = (sum(priv_key_ints) % b_order, sum(priv_key_ints) % w_order)
    assert agg_priv_int[0] == agg_priv_int[1], "Aggregated private keys do not match for both curves!"
    return agg_priv_int[0]

def main():
    # Load private keys
    priv_key_ints = load_private_keys(KEYS_DIR)
  
    # Aggregate private keys
    agg_priv_int = aggregate_private_keys(priv_key_ints)
    print(f"Aggregated Private Key (int): {agg_priv_int}")

    priv = PrivateKey(secret_exponent=agg_priv_int)
    pub = priv.get_public_key()

    
    

if __name__ == "__main__":
    main()