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
from modules.utils import Secp192r1, Secp256k1

SETUP_DIR = "../setup.json"
AGGKEY_DIR = "../outputs/participant"
OUTPUTS_DIR = "../outputs/participant/ecies_output"
KEYS_DIR = "../outputs/participant/keys"
PROOF_DIR = "../outputs/participant/proofs"


number_of_entities = 64
number_of_chunks = 3
b_x = 64 
b_f = 3
b_c = 124
b_g = 192
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


def compact_object(chunks):
    for id in range(number_of_chunks):
        if id == 0 :
            result = chunks[id]
        else: 
            result += chunks[id] * (2 ** (id * b_x)) 
    return result

def value_segmentation(value, secp192r1_curve): 
    assert value <= secp192r1_curve.field.n 
    value_bytes = value.to_bytes(Secp192r1.byte_size, 'big')

    # Calculate chunk size in bytes
    chunk_size = b_x // 8  # Use integer division

    chunks = []
    for i in range(number_of_chunks):
        start = i * chunk_size
        end = (i + 1) * chunk_size
        chunk = value_bytes[start:end]
        chunks.append(int.from_bytes(chunk, 'big'))

    # Return chunks in MSB-first order
    return chunks[::-1]


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

def challenge_computation(points): 
    input = bytes()
    for point in points: 
        if Secp256k1.is_on_curve(point):
            input += point.x.to_bytes(Secp256k1.byte_size, 'big') + point.y.to_bytes(Secp256k1.byte_size, 'big')
        elif Secp192r1.is_on_curve(point):
            input += point.x.to_bytes(Secp192r1.byte_size, 'big') + point.y.to_bytes(Secp192r1.byte_size, 'big')
        else : 
            raise('point is not on any of the curves')
    digest = hashlib.sha256(input).digest() 
    return int.from_bytes(digest, 'big')

def array_to_point(curve, array):
    points = [] 
    for id in range(len(array)): 
        try :
            points.append(Point(curve, array[id][0], array[id][1]))
        except:
            raise("point not on curve")
    return points

def iterate_proofs (H_256, H_192, secp256k1_curve, secp192r1_curve, private_key, number_of_carry_on_bits, MAX_ITER=1000):
    K_192, K_256, z, s_192, s_256, C_192_proof, C_256_proof, p_192_proof, p_256_proof = [], [], [], [], [], [], [], [], []
    r_256, r_192 = [], []
    assert (not number_of_carry_on_bits % number_of_chunks), "The number of carry on bits should divide the number of chunks"
    for chunk in range(number_of_chunks):
        r_256.append(secrets.randbelow(secp256k1_curve.field.n >> int(number_of_carry_on_bits/number_of_chunks)))
        r_192.append(secrets.randbelow(secp192r1_curve.field.n >> int(number_of_carry_on_bits/number_of_chunks)))
        if chunk == 0 :
            r_256_temp = r_256[chunk]
            r_192_temp = r_192[chunk]
            C_256_temp = private_key[chunk] * secp256k1_curve.generator() + H_256 * r_256[chunk]
            C_192_temp = private_key[chunk] * secp192r1_curve.generator() + H_192 * r_192[chunk]

        else: 
            r_256_temp = (r_256[chunk] * (2 ** (chunk * b_x))+ r_256_temp) % secp256k1_curve.field.n 
            r_192_temp = (r_192[chunk] * (2 ** (chunk * b_x))+ r_192_temp) % secp192r1_curve.field.n
            C_256_temp += private_key[chunk] * (2 ** (chunk * b_x)) * secp256k1_curve.generator() + H_256 * r_256[chunk] * (2 ** (chunk * b_x))
            C_192_temp += private_key[chunk] * (2 ** (chunk * b_x)) * secp192r1_curve.generator() + H_192 * r_192[chunk] * (2 ** (chunk * b_x))

        C_192_proof.append([(private_key[chunk] * secp192r1_curve.generator() + H_192 * r_192[chunk]).x, (private_key[chunk] * secp192r1_curve.generator() + H_192 * r_192[chunk]).y])
        C_256_proof.append([(private_key[chunk] * secp256k1_curve.generator() + H_256 * r_256[chunk]).x, (private_key[chunk] * secp256k1_curve.generator() + H_256 * r_256[chunk]).y])
        p_192_proof.append([(private_key[chunk] * secp192r1_curve.generator()).x, (private_key[chunk] * secp192r1_curve.generator()).y])
        p_256_proof.append([(private_key[chunk] * secp256k1_curve.generator()).x, (private_key[chunk] * secp256k1_curve.generator()).y])

        for i in range(MAX_ITER):
            # Generate fresh randomness
            t_256 = secrets.randbelow(secp256k1_curve.field.n)
            t_192 = secrets.randbelow(secp192r1_curve.field.n)
            k = secrets.randbelow(2 ** (b_x + b_c + b_f) -1)

            # Commitments in BTC curve
            K_256_temp = k * secp256k1_curve.generator() + t_256 * H_256

            # Commitments in NIST curve
            K_192_temp = k * secp192r1_curve.generator() + t_192 * H_192

            # Curve challenge
            curve_challenge = challenge_computation([K_256_temp, K_192_temp]) >> (256 - b_c) 

            # Compute z
            z_temp = k + curve_challenge * private_key[chunk] 
            if 2** (b_x + b_c) <= z_temp and z_temp < 2** (b_x+ b_c + b_f ) -1 :
                s_256.append((t_256 + curve_challenge * r_256[chunk]) % secp256k1_curve.field.n)
                s_192.append((t_192 + curve_challenge * r_192[chunk]) % secp192r1_curve.field.n)
                K_192.append([K_192_temp.x, K_192_temp.y])
                K_256.append([K_256_temp.x, K_256_temp.y])
                z.append(z_temp)
                break
        if (i > MAX_ITER):
            raise ValueError("Too many iterations in proof generation")
    return K_192, K_256, s_192  , s_256, z, C_192_proof, C_256_proof, p_192_proof, p_256_proof, r_192_temp, r_256_temp, C_192_temp, C_256_temp, r_256

def points_to_str(input):
    converted = []
    for element in input:
        if type(element) == list :
            # We have a list of points
            converted.append([str(element[0]), str(element[1])])
        elif type(element) == int :
            converted.append(str(element))
    return converted

def proof_gen(secp256k1_curve: Secp256k1, secp192r1_curve: Secp192r1):
    # Parameters in the Bitcoin's curve 
    H_256 = secp256k1_curve.map_to_point(secp256k1_curve.Gx.to_bytes(Secp256k1.byte_size, 'big') + secp256k1_curve.Gy.to_bytes(Secp256k1.byte_size, 'big'))
    H_192 = secp192r1_curve.map_to_point(secp192r1_curve.Gx.to_bytes(Secp192r1.byte_size, 'big') + secp192r1_curve.Gy.to_bytes(Secp192r1.byte_size, 'big'))
    private_key = derive_private_key()
    assert private_key.private_numbers().private_value <= secp192r1_curve.field.n >> over_flow_bits
    p_key_256 = secp256k1_curve.get_point(private_key.public_key().public_numbers().x, private_key.public_key().public_numbers().y)

    private_key_chunks = value_segmentation(private_key.private_numbers().private_value, secp192r1_curve)
    K_192, K_256, s_192, s_256, z, C_192_proof, C_256_proof, p_192_proof, p_256_proof, r_192, r_256, C_192_summed, C_256_summed, random_chunks = iterate_proofs(H_256, H_192, secp256k1_curve, secp192r1_curve, private_key_chunks, over_flow_bits)        # Cross-curve proofs

    C_256 = p_key_256 + (H_256 * r_256)
    assert C_256_summed.x == C_256.x and C_256.y == C_256_summed.y , "the addition of chunks does not add up in the commitments"

    #  Proof of knowledge of descrete log in the same curve 
    r_p_256 = secrets.randbelow(secp256k1_curve.field.n)
    r_c_256 = secrets.randbelow(secp256k1_curve.field.n)
    R_256 = r_p_256 * secp256k1_curve.generator()
    R_c_256 = r_p_256 * secp256k1_curve.generator()+ r_c_256 * H_256
    challenge = challenge_computation([R_256, R_c_256])
    alpha_p_256 = r_p_256 + (challenge * private_key.private_numbers().private_value) % secp256k1_curve.field.n
    alpha_c_256 = r_c_256 + (challenge * r_256) % secp256k1_curve.field.n
    # Parameters in the NIST P-192 curve
    p_key_192 = secp192r1_curve.generator() * private_key.private_numbers().private_value
    C_192 = p_key_192 + (H_192 * r_192)
    assert C_192_summed.x == C_192.x and C_192.y == C_192_summed.y , "the addition of chunks does not add up in the commitments"

    #  Proof of knowledge of descrete log in the same curve 
    r_p_192 = secrets.randbelow(secp192r1_curve.field.n)
    r_c_192 = secrets.randbelow(secp192r1_curve.field.n)
    R_192 = r_p_192 * secp192r1_curve.generator()
    R_c_192 = r_p_192 * secp192r1_curve.generator()+ r_c_192 * H_192 
    challenge = challenge_computation([R_192, R_c_192])
    alpha_p_192 = r_p_192 + (challenge * private_key.private_numbers().private_value) % secp192r1_curve.field.n
    alpha_c_192 = r_c_192 + (challenge * r_192) % secp192r1_curve.field.n

    # Proof parameters 
    json_data = {
        "p_256": p_256_proof,
        "p_192": p_192_proof,
        "R_256": [R_256.x, R_256.y],
        "R_c_256": [R_c_256.x, R_c_256.y],
        "K_256": K_256,
        "K_192": K_192,
        "C_192": C_192_proof,
        "C_256": C_256_proof,
        "R_192": [R_192.x, R_192.y],
        "R_c_192": [R_c_192.x, R_c_192.y],
        "z": z, 
        "s_192": s_192,
        "s_256": s_256, 
        "alpha_p_256": alpha_p_256,
        "alpha_c_256": alpha_c_256, 
        "alpha_p_192": alpha_p_192, 
        "alpha_c_192": alpha_c_192
    }
    json_SNARK_input = {
        "random_values": points_to_str(random_chunks), 
        "H": [str(H_256.x), str(H_256.y)], 
        "private_key": str(private_key.private_numbers().private_value), 
        "commitments": points_to_str(C_256_proof) , 
        "private_key_range": str(secp192r1_curve.field.n >> over_flow_bits)
    }
    if not os.path.exists(PROOF_DIR):
        os.makedirs(PROOF_DIR)
    with open(os.path.join(PROOF_DIR, f"proof_{private_key.public_key().public_numbers().x }.json"), "w") as proof_file:
        proof_file.write(json.dumps(json_data))
    with open(os.path.join(PROOF_DIR, f"input_SNARK_{private_key.public_key().public_numbers().x }.json"), "w") as input_file:
        input_file.write(json.dumps(json_SNARK_input))

if __name__ == "__main__":
    private_key = derive_private_key()
    proof_gen(Secp256k1, Secp192r1)

