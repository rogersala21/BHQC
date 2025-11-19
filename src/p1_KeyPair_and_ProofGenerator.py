import json
import os
import secrets
import math
import re
import subprocess
from cryptography.hazmat.primitives.asymmetric import ec
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from modules.curves import Secp192r1, Secp256k1
from modules.dleqag import DLEQAG
from modules.dleq import DLEQ
from modules.tools import to_snark_input

KEYS_DIR = "../outputs/participant/keys"
SETUP_DIR = "../setup.json"
PROOF_DIR = "../outputs/participant/proofs"

def load_setup():
    # Load setup data from JSON file
    if not os.path.exists(SETUP_DIR):
        print(f"Setup file not found: {SETUP_DIR}")
        return None
    with open(SETUP_DIR, "r") as setup_file:
        setup_data = json.load(setup_file)
    
    return setup_data

# seed bits calculation for key generation
def seed_bits_calc_keygen():
    setup_data = load_setup()
    if setup_data is None:
        return None
    num_participants = setup_data.get("num_participants")
    # Calculate bits of the seed (192-log2(n))
    bits_seed = 192 - math.log2(num_participants)
    return math.floor(bits_seed)

# seed bits calculation for proof generation
def seed_bits_calc_proofgen():
    setup_data = load_setup()
    if setup_data is None:
        return None
    num_participants = setup_data.get("num_participants")
    # Calculate bits of the seed (log2(n))
    bits_seed = math.log2(num_participants)
    return math.ceil(bits_seed)

def seedgen():
    # Use secrets to generate random bit sequence
    seed = secrets.randbits(seed_bits_calc_keygen())
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

    # save privat key to file
    priv_path = os.path.join(KEYS_DIR, f"private_key_{pub_x_int}_{network}_DO_NOT_SHARE.txt")
    with open(priv_path, "w") as priv_file:
        priv_file.write(priv.to_wif(compressed=True))


def derive_private_key():
    priv_key_int = load_private_key(KEYS_DIR)
    # Create EC private key object from integer
    priv_key = ec.derive_private_key(priv_key_int, ec.SECP256K1())
    return priv_key

def wif_to_int(wif):
    priv = PrivateKey(wif)
    priv_bytes = priv.to_bytes()
    di = int.from_bytes(priv_bytes, 'big')
    return di

def load_private_key(keys_dir):
    # Get the private key from the file
    files = [f for f in os.listdir(keys_dir) if re.match(r'private_key_.*_DO_NOT_SHARE\.txt', f)]
    if not files:
        raise FileNotFoundError(f"No private key file found in {keys_dir}")
    if len(files) > 1:
        raise FileExistsError(f"Multiple private key files found in {keys_dir}. Expected only one.")
    priv_key_filename = files[0]
    priv_key_path = os.path.join(keys_dir, priv_key_filename)
    # Extract network from filename
    match = re.search(r'_(mainnet|testnet)_DO_NOT_SHARE\.txt$', priv_key_filename)
    if not match:
        raise ValueError(f"Network not found in private key filename: {priv_key_filename}")
    network = match.group(1)
    setup(network)
    with open(priv_key_path, "r") as f:
        wif_key = f.read().strip()

    # Convert WIF to integer private key
    priv_key_int = wif_to_int(wif_key)
    return priv_key_int

def bulletproof_generation(input, number_of_chunks, b_x, over_flow_bits):
    assert b_x > over_flow_bits, "Too many participants."
    # node bulletproof_gen.js gen ../../../outputs/participant/proofs/ 64  234324732543246 345843754395643756263453276453267 0
    for index in range(number_of_chunks):
        result = subprocess.run(
        ["node", "./modules/bulletproofs/bulletproof.js", "gen", "../../../outputs/participant/proofs/", str( b_x - int(index == number_of_chunks -1) * over_flow_bits), str(input["private_key_chunks"][index]), str(input["random_chunks"][index]), str(index)],  # pass arguments
        capture_output=True,
        text=True
        )


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
    
    print("Generating your private key and saving into .txt files...\n")
    # Generation of seed
    seed = seedgen()
    # Generation of Bitcoin private key (dg)
    bitcoinkeygen(seed, network)
    print("Private key generated and saved successfully into ", KEYS_DIR)

def main_proofs():
    number_of_entities = 64
    number_of_chunks = 3
    b_x = 64 
    b_f = 3
    b_c = 124
    over_flow_bits = seed_bits_calc_proofgen()
    private_key = derive_private_key()
    private_key_range = Secp192r1.field.n >> over_flow_bits
    dleqag_inst = DLEQAG(b_x, b_f, b_c, number_of_chunks, private_key_range, Secp256k1, Secp192r1)
    dleqag_proof, SNARK_input, bulletproof_input = dleqag_inst.proof_gen(private_key.private_numbers().private_value)
    dleq_secp256k1_inst = DLEQ(Secp256k1)
    dleq_proof_secp256k1 = dleq_secp256k1_inst.proof_gen(dleqag_proof["r_HS"], private_key.private_numbers().private_value)
    dleq_secp192r1_inst = DLEQ(Secp192r1)
    dleq_proof_secp192r1 = dleq_secp192r1_inst.proof_gen(dleqag_proof["r_LS"],  private_key.private_numbers().private_value)
    json_data = {
        "pub_key_256": dleqag_proof["pub_key_HS"],
        "pub_key_192": dleqag_proof["pub_key_LS"],
        "p_256": dleqag_proof["p_HS"],
        "K_256": dleqag_proof["K_HS"],
        "C_256": dleqag_proof["C_HS"],
        "s_256": dleqag_proof["s_HS"], 
        "p_192": dleqag_proof["p_LS"],
        "K_192": dleqag_proof["K_LS"],
        "C_192": dleqag_proof["C_LS"],
        "s_192": dleqag_proof["s_LS"],
        "z": dleqag_proof["z"], 
        "dleq_192": dleq_proof_secp192r1, 
        "dleq_256": dleq_proof_secp256k1
    }
    bulletproof_generation(bulletproof_input, number_of_chunks, b_x, over_flow_bits)
    SNARK_input = to_snark_input(SNARK_input)
    if not os.path.exists(PROOF_DIR):
        os.makedirs(PROOF_DIR)
    with open(os.path.join(PROOF_DIR, f"proof_{private_key.public_key().public_numbers().x }.json"), "w") as proof_file:
        proof_file.write(json.dumps(json_data))
    with open(os.path.join(PROOF_DIR, f"input_SNARK_{private_key.public_key().public_numbers().x }.json"), "w") as input_file:
        input_file.write(json.dumps(SNARK_input))
    
    print("Proofs generated and saved successfully into ", PROOF_DIR)

if __name__ == "__main__":
    main()
    main_proofs()
