import os
import hashlib
import re
from cryptography.hazmat.primitives.asymmetric import ec
from tinyec.ec import Point
from tinyec.ec import SubGroup, Curve
import secrets
import json
from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup


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

number_of_entities = 16
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

    setup(network)

    # Get the private key from the file
    files = [f for f in os.listdir(keys_dir) if re.match(r'private_key_.*_DO_NOT_SHARE\.txt', f)]
    if not files:
        raise FileNotFoundError(f"No private key file found in {keys_dir}")
    if len(files) > 1:
        raise FileExistsError(f"Multiple private key files found in {keys_dir}. Expected only one.")
    priv_key_path = os.path.join(keys_dir, files[0])
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


def proof_gen(private_key):
    v, k = priv_key_segmentation(private_key.private_numbers().private_value) 
    assert(v < weak_curve.field.n)
    assert(k < weak_curve.field.n)
    v_bytes, k_bytes = padding(v, k)
    public_key_v = btc_curve.g * v_bytes
    public_key_k = btc_curve.g * k_bytes

    #  checking if the points are equal and correctly calculated
    padded_point = (public_key_v * (1 << 128) + public_key_k)
    assert(padded_point.x == private_key.public_key().public_numbers().x )
    assert(padded_point.y == private_key.public_key().public_numbers().y )    
   

    enc_point_v = weak_curve.g * v_bytes
    enc_point_k = weak_curve.g * k_bytes

    # Proof parameters 
    # Imporytant: Note that r_v and r_k are in the weaker curve's field

    r_v = secrets.randbelow(weak_curve.field.n)
    r_k = secrets.randbelow(weak_curve.field.n)
    R_prime_v = weak_curve.g * r_v
    R_prime_k = weak_curve.g * r_k
    R_v = btc_curve.g * r_v
    R_k = btc_curve.g * r_k

    #  Put the context better 
    m = hashlib.sha256(R_v.x.to_bytes(size_btc, 'big') + R_v.y.to_bytes(size_btc, 'big'))
    m.update(R_prime_v.x.to_bytes(size_weak, 'big') + R_prime_v.y.to_bytes(size_weak, 'big'))
    m.update(R_k.x.to_bytes(size_btc, 'big') + R_k.y.to_bytes(size_btc, 'big'))
    m.update(R_prime_k.x.to_bytes(size_weak, 'big') + R_prime_k.y.to_bytes(size_weak, 'big'))
    m.update(public_key_v.x.to_bytes(size_btc, 'big') + public_key_v.y.to_bytes(size_btc, 'big'))
    m.update(public_key_k.x.to_bytes(size_btc, 'big') + public_key_k.y.to_bytes(size_btc, 'big'))
    m.update(enc_point_v.x.to_bytes(size_weak, 'big') + enc_point_v.y.to_bytes(size_weak, 'big'))
    m.update(enc_point_k.x.to_bytes(size_weak, 'big') + enc_point_k.y.to_bytes(size_weak, 'big'))
    m.update(btc_curve.g.x.to_bytes(size_btc, 'big'))
    m.update(weak_curve.g.x.to_bytes(size_weak, 'big'))
    digest_int = int.from_bytes(m.digest(), "big") 

    s_v = (r_v + digest_int * v_bytes) 
    s_k = (r_k + digest_int * k_bytes) 
    
    json_data = {
        "R_v": [R_v.x, R_v.y],
        "R_k": [R_k.x, R_k.y],
        "R'_v": [R_prime_v.x, R_prime_v.y],
        "R'_k": [R_prime_k.x, R_prime_k.y],
        "s_v": s_v,
        "s_k": s_k,
        "public_key_v": [public_key_v.x, public_key_v.y],
        "public_key_k": [public_key_k.x, public_key_k.y],
        "enc_point_v": [enc_point_v.x, enc_point_v.y],
        "enc_point_k": [enc_point_k.x, enc_point_k.y]
    }
    if not os.path.exists(PROOF_DIR):
        os.makedirs(PROOF_DIR)
    with open(os.path.join(PROOF_DIR, f"proof_{private_key.public_key().public_numbers().x }.json"), "w") as f:
        f.write(json.dumps(json_data))

def proof_verification(json_data):
    R_v = Point(btc_curve, json_data["R_v"][0], json_data["R_v"][1])
    R_k = Point(btc_curve, json_data["R_k"][0], json_data["R_k"][1])
    R_prime_v = Point(weak_curve, json_data["R'_v"][0], json_data["R'_v"][1])
    R_prime_k = Point(weak_curve, json_data["R'_k"][0], json_data["R'_k"][1])
    s_v = json_data["s_v"]
    s_k = json_data["s_k"]
    public_key_v = Point(btc_curve, json_data["public_key_v"][0], json_data["public_key_v"][1])
    public_key_k = Point(btc_curve, json_data["public_key_k"][0], json_data["public_key_k"][1])
    enc_point_v = Point(weak_curve, json_data["enc_point_v"][0], json_data["enc_point_v"][1])
    enc_point_k = Point(weak_curve, json_data["enc_point_k"][0], json_data["enc_point_k"][1])    

    m = hashlib.sha256(R_v.x.to_bytes(size_btc, 'big') + R_v.y.to_bytes(size_btc, 'big'))
    m.update(R_prime_v.x.to_bytes(size_weak, 'big') + R_prime_v.y.to_bytes(size_weak, 'big'))
    m.update(R_k.x.to_bytes(size_btc, 'big') + R_k.y.to_bytes(size_btc, 'big'))
    m.update(R_prime_k.x.to_bytes(size_weak, 'big') + R_prime_k.y.to_bytes(size_weak, 'big'))
    m.update(public_key_v.x.to_bytes(size_btc, 'big') + public_key_v.y.to_bytes(size_btc, 'big'))
    m.update(public_key_k.x.to_bytes(size_btc, 'big') + public_key_k.y.to_bytes(size_btc, 'big'))
    m.update(enc_point_v.x.to_bytes(size_weak, 'big') + enc_point_v.y.to_bytes(size_weak, 'big'))
    m.update(enc_point_k.x.to_bytes(size_weak, 'big') + enc_point_k.y.to_bytes(size_weak, 'big'))
    m.update(btc_curve.g.x.to_bytes(size_btc, 'big'))
    m.update(weak_curve.g.x.to_bytes(size_weak, 'big'))
    digest_int = int.from_bytes(m.digest(), "big")  

    #  Check the signature validity
    # ===== Verification on weak curve (per paper: s_v * G192 == R'_v + m * C'_v) =====
    lhs_weak = weak_curve.g * (s_v % weak_curve.field.n)
    rhs_weak = R_prime_v + enc_point_v * (digest_int % weak_curve.field.n)
    assert lhs_weak.x == rhs_weak.x and lhs_weak.y == rhs_weak.y, "Weak-curve check failed for the higher bits"

    lhs_weak = weak_curve.g * (s_k % weak_curve.field.n)
    rhs_weak = R_prime_k + enc_point_k * (digest_int % weak_curve.field.n)
    assert lhs_weak.x == rhs_weak.x and lhs_weak.y == rhs_weak.y, "Weak-curve check failed for the lower bits"

    # ===== Verification on BTC curve (per paper: s_v * G256 == R_v + m * P_vi) =====

    lhs_btc = btc_curve.g * (s_v % btc_curve.field.n)
    rhs_btc = R_v + public_key_v * (digest_int % btc_curve.field.n)
    assert lhs_btc.x == rhs_btc.x and lhs_btc.y == rhs_btc.y, "BTC-curve check failed on the higher bits"

    lhs_weak = btc_curve.g * (s_k % btc_curve.field.n)
    rhs_weak = R_k + public_key_k * (digest_int % btc_curve.field.n)
    assert lhs_btc.x == rhs_btc.x and lhs_btc.y == rhs_btc.y, "BTC-curve check failed for the lower bits"
    print("Proof is verified.")

if __name__ == "__main__":
    private_key = derive_private_key()
    proof_gen(private_key)
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
