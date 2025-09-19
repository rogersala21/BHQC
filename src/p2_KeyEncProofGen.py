import os
import hashlib
import re
import secrets
import json
from cryptography.hazmat.primitives.asymmetric import ec
from tinyec.ec import Point
from tinyec.ec import SubGroup, Curve
from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup

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
key_chunk_size = 64
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
number_of_entities = 16
# To do : handle the case of non-power of 2
# over_flow_bits = math.log2(number_of_entities)
over_flow_bits = 4
padding_range = 64  # Number of bits for padding

AGGKEY_DIR = "../outputs/participant"
OUTPUTS_DIR = "../outputs/participant/ecies_output"
KEYS_DIR = "../outputs/participant/keys"
PROOF_DIR = "../outputs/participant/proofs"


def priv_key_segmentation(priv_key): 
    assert priv_key <= btc_curve.field.n
    v_bytes = priv_key >> 128
    k_bytes = priv_key & ((1 << 128) - 1)
    return v_bytes, k_bytes

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

def dummy_priv_key(): 
    priv_key_value = secrets.randbelow(2 ** key_chunk_size)
    priv_key = ec.derive_private_key(priv_key_value, ec.SECP256K1())
    assert(priv_key.private_numbers().private_value == priv_key_value)
    return priv_key


def iterate_proofs (r_256, H_256, r_192, H_192, btc_curve, weak_curve, private_key, MAX_ITER=100):
    for i in range(MAX_ITER):
        # Generate fresh randomness
        t_256 = secrets.randbelow(2 ** key_chunk_size)
        t_192 = secrets.randbelow(2 ** key_chunk_size)
        k = secrets.randbelow(weak_curve.field.n)

        # Commitments in BTC curve
        K_256 = k * btc_curve.g + t_256 * H_256

        # Commitments in NIST curve
        K_192 = k * weak_curve.g + t_192 * H_192

        # Curve challenge
        curve_challenge = challenge_computation([K_256, K_192]) >> 132

        # Compute z
        z = k + curve_challenge * private_key.private_numbers().private_value

        if 2**188 <= z < weak_curve.field.n:
            s_256 = (t_256 + curve_challenge * r_256) % btc_curve.field.n
            s_192 = (t_192 + curve_challenge * r_192) % weak_curve.field.n
            return  K_256, K_192, z, s_192, s_256

    raise ValueError("Too many iterations in proof generation")


def proof_gen():
    # Parameters in the Bitcoin's curve 
    private_key = dummy_priv_key()
    p_key_256 = Point(btc_curve, private_key.public_key().public_numbers().x, private_key.public_key().public_numbers().y)
    r_256 = secrets.randbelow(2 ** key_chunk_size)
    C_256 = p_key_256 + (H_256 * r_256)
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
    r_192 = secrets.randbelow(2 ** key_chunk_size)
    C_192 = p_key_192 + (H_192 * r_192)
    #  Proof of knowledge of descrete log in the same curve 
    r_p_192 = secrets.randbelow(weak_curve.field.n)
    r_c_192 = secrets.randbelow(weak_curve.field.n)
    R_192 = r_p_192 * weak_curve.g
    R_c_192 = r_p_192 * weak_curve.g + r_c_192 * H_192 
    challenge = challenge_computation([R_192, R_c_192])

    alpha_p_192 = r_p_192 + (challenge * private_key.private_numbers().private_value) % weak_curve.field.n
    alpha_c_192 = r_c_192 + (challenge * r_192) % weak_curve.field.n
    K_256, K_192, z, s_192, s_256 = iterate_proofs(r_256, H_256, r_192, H_192, btc_curve, weak_curve, private_key)

    # Proof parameters 
    json_data = {
        "p_256": [p_key_256.x, p_key_256.y],
        "p_192": [p_key_192.x, p_key_192.y],
        "R_256": [R_256.x, R_256.y],
        "R_c_256": [R_c_256.x, R_c_256.y],
        "K_256": [K_256.x, K_256.y],
        "K_192": [K_192.x, K_192.y],
        "C_192": [C_192.x, C_192.y],
        "C_256": [C_256.x, C_256.y],
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
    p_256 = Point(btc_curve, json_data["p_256"][0], json_data["p_256"][1])
    p_192 = Point(weak_curve, json_data["p_192"][0], json_data["p_192"][1])
    R_256 = Point(btc_curve, json_data["R_256"][0], json_data["R_256"][1])
    R_c_256 = Point(btc_curve, json_data["R_c_256"][0], json_data["R_c_256"][1])
    R_192 = Point(weak_curve, json_data["R_192"][0], json_data["R_192"][1])
    R_c_192 = Point(weak_curve, json_data["R_c_192"][0], json_data["R_c_192"][1])   
    s_192 = json_data["s_192"]
    s_256 = json_data["s_256"]
    K_256 = Point(btc_curve, json_data["K_256"][0], json_data["K_256"][1])
    K_192 = Point(weak_curve, json_data["K_192"][0], json_data["K_192"][1])
    C_192 = Point(weak_curve, json_data["C_192"][0], json_data["C_192"][1])
    C_256 = Point(btc_curve, json_data["C_256"][0], json_data["C_256"][1])    
    z = json_data["z"]
    alpha_p_256 = json_data["alpha_p_256"]
    alpha_c_256 = json_data["alpha_c_256"]

    alpha_p_192 = json_data["alpha_p_192"]
    alpha_c_192 = json_data["alpha_c_192"]



    curve_challenge = challenge_computation([K_256, K_192]) >> 132 
    assert z >= 2** 188 and z < weak_curve.field.n, "z is out of range"

    #  Check the signature validity
    # ===== Verification on weak curve (per paper: s_v * G192 == R'_v + m * C'_v) =====
    lhs_weak = weak_curve.g * z + s_192 * H_192
    rhs_weak = K_192 + curve_challenge * C_192
    assert lhs_weak.x == rhs_weak.x and lhs_weak.y == rhs_weak.y, "Weak-curve check failed for the transition between curves"

    # ===== Verification on NIST curve =====  
    challenge = challenge_computation([R_192, R_c_192]) 
    lhs = alpha_p_192 * weak_curve.g 
    rhs = R_192 + challenge * p_192
    assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment"
    rhs = alpha_p_192 * weak_curve.g + alpha_c_192 * H_192
    lhs = R_c_192 + challenge * C_192
    assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment with blinding factor"

    # ===== Verification on BTC curve =====   
    challenge = challenge_computation([R_256, R_c_256])
    lhs = alpha_p_256 * btc_curve.g 
    rhs = R_256 + challenge * p_256
    assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment"
    rhs = alpha_p_256 * btc_curve.g + alpha_c_256 * H_256
    lhs = R_c_256 + challenge * C_256
    assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment with blinding factor"

    # ===== Verification on BTC curve transition to NIST  =====

    lhs_btc = btc_curve.g * z + s_256 * H_256
    rhs_btc = K_256 + curve_challenge * C_256
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
