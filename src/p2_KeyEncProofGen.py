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

SETUP_DIR = "../setup.json"

def point_extraction(curve, seed):
    while True:
        digest = hashlib.sha256(seed).digest()
        x = int.from_bytes(digest, 'big') % p

        rhs = (x**3 + curve.a *x + curve.b ) % p
        if pow(rhs, (p - 1) // 2, p) == 1:
            y = pow(rhs, (p + 1) // 4, p)
            return Point(curve, x, y)

        seed = hashlib.sha256(seed).digest()
    
# SECP256K1 parameters
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
a  = 0
b  = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
field = SubGroup(p, g =(Gx, Gy), n=n, h=1)
btc_curve = Curve(a, b, field, name='secp256k1')
size_btc = 32
H_256 = point_extraction(btc_curve, btc_curve.g.x.to_bytes(size_btc, 'big') + btc_curve.g.y.to_bytes(size_btc, 'big'))



# SECP192R1 parameters
p  = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
a  = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
b  = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
n  = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
field = SubGroup(p, g=(Gx, Gy), n=n, h=1)
weak_curve = Curve(a, b, field, name='secp192r1')
size_weak = 24
H_192 = point_extraction(weak_curve, weak_curve.g.x.to_bytes(size_weak, 'big') + weak_curve.g.y.to_bytes(size_weak, 'big'))

# TODO Scheme setup parameters (put onto a setup file later)

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
padding_range = 64  # Number of bits for padding

AGGKEY_DIR = "../outputs/participant"
OUTPUTS_DIR = "../outputs/participant/ecies_output"
KEYS_DIR = "../outputs/participant/keys"
PROOF_DIR = "../outputs/participant/proofs"

def compact_object(chunks):
    for id in range(number_of_chunks):
        if id == 0 :
            result = chunks[id]
        else: 
            result += chunks[id] * (2 ** (id * b_x)) 
    return result

def value_segmentation(value): 
    assert value <= weak_curve.field.n 
    value_bytes = value.to_bytes(size_weak, 'big')

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

def is_on_curve(point, curve):
    x, y = point.x, point.y
    lhs = y * y % curve.field.p
    rhs = (x**3 + curve.a * x + curve.b) % curve.field.p
    return lhs == rhs

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

def padding(v_bytes, k_bytes):
    a_bytes = secrets.randbelow(1 << padding_range)
    v_padded = (v_bytes + a_bytes) % btc_curve.field.n
    k_padded = (k_bytes - a_bytes * (1 << 128)) % btc_curve.field.n
    return v_padded, k_padded

def challenge_computation(points): 
    input = bytes()
    for point in points: 
        if is_on_curve(point, btc_curve):
            input += point.x.to_bytes(size_btc, 'big') + point.y.to_bytes(size_btc, 'big')
        elif is_on_curve(point, weak_curve):
            input += point.x.to_bytes(size_weak, 'big') + point.y.to_bytes(size_weak, 'big')
        else : 
            raise('point is not on any of the curves')
    digest = hashlib.sha256(input).digest() 
    return int.from_bytes(digest, 'big')

#def dummy_priv_key(): 
#    priv_key_value = secrets.randbelow(2 ** (192 - over_flow_bits))
#    priv_key = ec.derive_private_key(priv_key_value, ec.SECP256K1())
#    assert(priv_key.private_numbers().private_value == priv_key_value)
#    return priv_key

def array_to_point(curve, array):
    points = [] 
    for id in range(len(array)): 
        try :
            points.append(Point(curve, array[id][0], array[id][1]))
        except:
            raise("point not on curve")
    return points

def iterate_proofs (H_256, H_192, btc_curve, weak_curve, private_key, number_of_carry_on_bits, MAX_ITER=1000):
    K_192, K_256, z, s_192, s_256, C_192_proof, C_256_proof, p_192_proof, p_256_proof = [], [], [], [], [], [], [], [], []
    r_256, r_192 = [], []
    assert (not number_of_carry_on_bits % number_of_chunks), "The number of carry on bits should divide the number of chunks"
    for chunk in range(number_of_chunks):
        r_256.append(secrets.randbelow(btc_curve.field.n >> int(number_of_carry_on_bits/number_of_chunks)))
        r_192.append(secrets.randbelow(weak_curve.field.n >> int(number_of_carry_on_bits/number_of_chunks)))
        if chunk == 0 :
            r_256_temp = r_256[chunk]
            r_192_temp = r_192[chunk]
            C_256_temp = private_key[chunk] * btc_curve.g + H_256 * r_256[chunk]
            C_192_temp = private_key[chunk] * weak_curve.g + H_192 * r_192[chunk]

        else: 
            r_256_temp = (r_256[chunk] * (2 ** (chunk * b_x))+ r_256_temp) % btc_curve.field.n 
            r_192_temp = (r_192[chunk] * (2 ** (chunk * b_x))+ r_192_temp) % weak_curve.field.n
            C_256_temp += private_key[chunk] * (2 ** (chunk * b_x)) * btc_curve.g + H_256 * r_256[chunk] * (2 ** (chunk * b_x))
            C_192_temp += private_key[chunk] * (2 ** (chunk * b_x)) * weak_curve.g + H_192 * r_192[chunk] * (2 ** (chunk * b_x))

        C_192_proof.append([(private_key[chunk] * weak_curve.g + H_192 * r_192[chunk]).x, (private_key[chunk] * weak_curve.g + H_192 * r_192[chunk]).y])
        C_256_proof.append([(private_key[chunk] * btc_curve.g + H_256 * r_256[chunk]).x, (private_key[chunk] * btc_curve.g + H_256 * r_256[chunk]).y])
        p_192_proof.append([(private_key[chunk] * weak_curve.g).x, (private_key[chunk] * weak_curve.g).y])
        p_256_proof.append([(private_key[chunk] * btc_curve.g).x, (private_key[chunk] * btc_curve.g).y])

        for i in range(MAX_ITER):
            # Generate fresh randomness
            t_256 = secrets.randbelow(btc_curve.field.n)
            t_192 = secrets.randbelow(weak_curve.field.n)
            k = secrets.randbelow(2 ** (b_x + b_c + b_f) -1)

            # Commitments in BTC curve
            K_256_temp = k * btc_curve.g + t_256 * H_256

            # Commitments in NIST curve
            K_192_temp = k * weak_curve.g + t_192 * H_192

            # Curve challenge
            curve_challenge = challenge_computation([K_256_temp, K_192_temp]) >> (256 - b_c) 

            # Compute z
            z_temp = k + curve_challenge * private_key[chunk] 
            if 2** (b_x + b_c) <= z_temp and z_temp < 2** (b_x+ b_c + b_f ) -1 :
                s_256.append((t_256 + curve_challenge * r_256[chunk]) % btc_curve.field.n)
                s_192.append((t_192 + curve_challenge * r_192[chunk]) % weak_curve.field.n)
                K_192.append([K_192_temp.x, K_192_temp.y])
                K_256.append([K_256_temp.x, K_256_temp.y])
                z.append(z_temp)
                break
        if (i > MAX_ITER):
            raise ValueError("Too many iterations in proof generation")
    return K_192, K_256, s_192  , s_256, z, C_192_proof, C_256_proof, p_192_proof, p_256_proof, r_192_temp, r_256_temp, C_192_temp, C_256_temp


def proof_gen():
    # Parameters in the Bitcoin's curve 
    private_key = derive_private_key()
    assert private_key.private_numbers().private_value <= weak_curve.field.n >> over_flow_bits
    p_key_256 = Point(btc_curve, private_key.public_key().public_numbers().x, private_key.public_key().public_numbers().y)

    private_key_chunks = value_segmentation(value=private_key.private_numbers().private_value)
    K_192, K_256, s_192, s_256, z, C_192_proof, C_256_proof, p_192_proof, p_256_proof, r_192, r_256, C_192_summed, C_256_summed = iterate_proofs(H_256, H_192, btc_curve, weak_curve, private_key_chunks, over_flow_bits)        # Cross-curve proofs

    C_256 = p_key_256 + (H_256 * r_256)
    assert C_256_summed.x == C_256.x and C_256.y == C_256_summed.y , "the addition of chunks does not add up in the commitments"

    #  Proof of knowledge of descrete log in the same curve 
    r_p_256 = secrets.randbelow(btc_curve.field.n)
    r_c_256 = secrets.randbelow(btc_curve.field.n)
    R_256 = r_p_256 * btc_curve.g
    R_c_256 = r_p_256 * btc_curve.g + r_c_256 * H_256
    challenge = challenge_computation([R_256, R_c_256])
    alpha_p_256 = r_p_256 + (challenge * private_key.private_numbers().private_value) % btc_curve.field.n
    alpha_c_256 = r_c_256 + (challenge * r_256) % btc_curve.field.n
    # Parameters in the NIST P-192 curve
    p_key_192 = weak_curve.g * private_key.private_numbers().private_value
    C_192 = p_key_192 + (H_192 * r_192)
    assert C_192_summed.x == C_192.x and C_192.y == C_192_summed.y , "the addition of chunks does not add up in the commitments"

    #  Proof of knowledge of descrete log in the same curve 
    r_p_192 = secrets.randbelow(weak_curve.field.n)
    r_c_192 = secrets.randbelow(weak_curve.field.n)
    R_192 = r_p_192 * weak_curve.g
    R_c_192 = r_p_192 * weak_curve.g + r_c_192 * H_192 
    challenge = challenge_computation([R_192, R_c_192])
    alpha_p_192 = r_p_192 + (challenge * private_key.private_numbers().private_value) % weak_curve.field.n
    alpha_c_192 = r_c_192 + (challenge * r_192) % weak_curve.field.n

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
    if not os.path.exists(PROOF_DIR):
        os.makedirs(PROOF_DIR)
    with open(os.path.join(PROOF_DIR, f"proof_{private_key.public_key().public_numbers().x }.json"), "w") as f:
        f.write(json.dumps(json_data))

def proof_verification(json_data):
    R_256 = Point(btc_curve, json_data["R_256"][0], json_data["R_256"][1]) 
    R_c_256 = Point(btc_curve, json_data["R_c_256"][0], json_data["R_c_256"][1])
    R_192 = Point(weak_curve, json_data["R_192"][0], json_data["R_192"][1])
    R_c_192 = Point(weak_curve, json_data["R_c_192"][0], json_data["R_c_192"][1]) 
    s_192 = json_data["s_192"]
    s_256 = json_data["s_256"]
    C_256 = array_to_point(btc_curve, json_data["C_256"])
    K_256 = array_to_point(btc_curve, json_data["K_256"])
    p_256 = array_to_point(btc_curve, json_data["p_256"])
    C_192 = array_to_point(weak_curve, json_data["C_192"])
    K_192 = array_to_point(weak_curve, json_data["K_192"])
    p_192 = array_to_point(weak_curve, json_data["p_192"])

    z = json_data["z"]
    alpha_p_256 = json_data["alpha_p_256"]
    alpha_c_256 = json_data["alpha_c_256"]

    alpha_p_192 = json_data["alpha_p_192"]
    alpha_c_192 = json_data["alpha_c_192"]
    p_256_proof = compact_object(p_256)
    p_192_proof = compact_object(p_192)
    C_256_proof = compact_object(C_256)
    C_192_proof = compact_object(C_192)

    # ===== Verification on NIST curve =====  
    challenge = challenge_computation([R_192, R_c_192]) 
    lhs = alpha_p_192 * weak_curve.g 
    rhs = R_192 + challenge * p_192_proof
    assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment"
    rhs = alpha_p_192 * weak_curve.g + alpha_c_192 * H_192
    lhs = R_c_192 + challenge * C_192_proof
    assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment with blinding factor"

    # ===== Verification on BTC curve =====   
    challenge = challenge_computation([R_256, R_c_256])
    lhs = alpha_p_256 * btc_curve.g 
    rhs = R_256 + challenge * p_256_proof
    assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment"
    rhs = alpha_p_256 * btc_curve.g + alpha_c_256 * H_256
    lhs = R_c_256 + challenge * C_256_proof
    assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment with blinding factor"

    # ====== Check the transitions on chunks ==========  
    for id in range(number_of_chunks):
        curve_challenge = challenge_computation([K_256[id], K_192[id]]) >> 132 
        assert    2** (b_x + b_c) <= z[id] and z[id] < 2** (b_x+ b_c + b_f ) -1 , "z is out of range"

        #  Check the signature validity
        # ===== Verification on weak curve (per paper: s_v * G192 == R'_v + m * C'_v) =====
        lhs_weak = weak_curve.g * z[id] + s_192[id] * H_192
        rhs_weak = K_192[id] + curve_challenge * C_192[id]
        assert lhs_weak.x == rhs_weak.x and lhs_weak.y == rhs_weak.y, "Weak-curve check failed for the transition between curves"


        # ===== Verification on BTC curve transition to NIST  =====

        lhs_btc = btc_curve.g * z[id] + s_256[id] * H_256
        rhs_btc = K_256[id] + curve_challenge * C_256[id]
        assert lhs_btc.x == rhs_btc.x and lhs_btc.y == rhs_btc.y, "BTC-curve check failed on the transition between curves"

    print("Proof is verified.")

if __name__ == "__main__":
    # private_key = derive_private_key()
    proof_gen()
    if not os.path.exists(PROOF_DIR):
        raise FileNotFoundError(f"Proof directory does not exist: {PROOF_DIR}")

    # Look for all proof files in the directory
    files = [f for f in os.listdir(PROOF_DIR) if f.endswith(".json")]
    if not files:
        raise FileNotFoundError(f"No proof files found in {PROOF_DIR}")

    for filename in files:
        filepath = os.path.join(PROOF_DIR, filename)
        with open(filepath, "r") as f:
            json_data = json.load(f)

        print(f"Verifying proof from: {filename}")
        proof_verification(json_data) 
