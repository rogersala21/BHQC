import os
import hashlib
import re
import secrets
import json
import math
from cryptography.hazmat.primitives.asymmetric import ec
from tinyec.ec import Point
from tinyec.ec import SubGroup, Curve
from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup
from modules.curves import Secp192r1, Secp256k1
from modules.dleqag import DLEQAG
from modules.dleq import DLEQ

SETUP_DIR = "../setup.json"
AGGKEY_DIR = "../outputs/participant"
OUTPUTS_DIR = "../outputs/participant/ecies_output"
KEYS_DIR = "../outputs/participant/keys"
PROOF_DIR = "../outputs/participant/proofs"



# To do : handle the case of non-power of 2
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
    # Calculate bits of the seed (log2(n))
    bits_seed = math.log2(num_participants)
    return math.ceil(bits_seed)
# over_flow_bits = math.log2(number_of_entities)
over_flow_bits = seed_bits_calc()


def aggregate_chunks(chunks):
    for id in range(number_of_chunks):
        if id == 0 :
            result = chunks[id]
        else: 
            result += chunks[id] * (2 ** (id * b_x)) 
    return result

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



if __name__ == "__main__":
    number_of_entities = 64
    number_of_chunks = 3
    b_x = 64 
    b_f = 3
    b_c = 124
    private_key = derive_private_key()
    private_key_range = Secp192r1.field.n >> over_flow_bits
    dleqag_inst = DLEQAG(b_x, b_f, b_c, number_of_chunks, private_key_range, Secp256k1, Secp192r1)
    dleqag_proof, SNARK_input = dleqag_inst.proof_gen(private_key.private_numbers().private_value)
    dleq_secp256k1_inst = DLEQ(Secp256k1)
    dleq_proof_secp256k1 = dleq_secp256k1_inst.proof_gen(dleqag_proof["r_HS"], private_key.private_numbers().private_value)
    dleq_secp192r1_inst = DLEQ(Secp192r1)
    dleq_proof_secp192r1 = dleq_secp192r1_inst.proof_gen(dleqag_proof["r_LS"],  private_key.private_numbers().private_value)
    json_data = {
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
    if not os.path.exists(PROOF_DIR):
        os.makedirs(PROOF_DIR)
    with open(os.path.join(PROOF_DIR, f"proof_{private_key.public_key().public_numbers().x }.json"), "w") as proof_file:
        proof_file.write(json.dumps(json_data))
    with open(os.path.join(PROOF_DIR, f"input_SNARK_{private_key.public_key().public_numbers().x }.json"), "w") as input_file:
        input_file.write(json.dumps(SNARK_input))

