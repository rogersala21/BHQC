import json
import os
from coincurve import PublicKey
from tinyec import registry
from tinyec.ec import Point
from tinyec.ec import SubGroup, Curve
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import hashlib
PROOF_DIR = "../outputs/participant/proofs"
OUTPUTS_DIR = "../outputs/coordinator/key_agg_output"

# SECP256K1 parameters
p_256  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n_256  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
a_256  = 0
b_256  = 7
Gx_256 = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy_256 = 32670510020758816978083085130507043184471273380659243275938904335757337482424
field_256 = SubGroup(p_256, g=(Gx_256, Gy_256), n=n_256, h=1)
btc_curve = Curve(a_256, b_256, field_256, name='secp256k1')

# SECP192R1 parameters  
p_192  = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
a_192  = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
b_192  = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
Gx_192 = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
Gy_192 = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
n_192  = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
field_192 = SubGroup(p_192, g=(Gx_192, Gy_192), n=n_192, h=1)
weak_curve = Curve(a_192, b_192, field_192, name='secp192r1')
number_of_entities = 64
number_of_chunks = 3
b_x = 64 
b_f = 3
b_c = 124
b_g = 192
size_weak = 24
size_btc = 32

def point_extraction(curve,p, seed):
    while True:
        digest = hashlib.sha256(seed).digest()
        x = int.from_bytes(digest, 'big') % p

        rhs = (x**3 + curve.a *x + curve.b ) % p
        if pow(rhs, (p - 1) // 2, p) == 1:
            y = pow(rhs, (p + 1) // 4, p)
            return Point(curve, x, y)

        seed = hashlib.sha256(seed).digest()

H_256 = point_extraction(btc_curve, p_256, btc_curve.g.x.to_bytes(size_btc, 'big') + btc_curve.g.y.to_bytes(size_btc, 'big'))

H_192 = point_extraction(weak_curve, p_192, weak_curve.g.x.to_bytes(size_weak, 'big') + weak_curve.g.y.to_bytes(size_weak, 'big'))

def load_public_keys(proof_dir):
    btc_pubkeylist = []
    secp192_pubkeylist = []
    for filename in os.listdir(proof_dir):
        file_path = os.path.join(proof_dir, filename)
        if os.path.isfile(file_path) and filename.startswith("proof_") and filename.endswith(".json"):
            with open(file_path, "r") as f:
                data = json.load(f)

                btc_pubkey_chunks = data.get("p_256")
                secp192_pubkey_chunks = data.get("p_192")

                if len(btc_pubkey_chunks) == len(secp192_pubkey_chunks) and len(btc_pubkey_chunks) > 0:

                        # Convert secp256k1 to Point
                        p_256_points = array_to_point(btc_curve, btc_pubkey_chunks)
                        # Compact_object to reconstruct
                        reconstructed_btc_point = compact_object(p_256_points)
                        
                        try:
                            pubkey_btc = PublicKey.from_point(reconstructed_btc_point.x, reconstructed_btc_point.y)
                            btc_pubkeylist.append(pubkey_btc)
                        except Exception as e:
                            print(f"Error creating BTC PublicKey: {e}")


                        # Convert secp192r1 to Point object
                        p_192_points = array_to_point(weak_curve, secp192_pubkey_chunks)
                        # Compact_object to reconstruct
                        reconstructed_secp192_point = compact_object(p_192_points)
                        
                        secp192_pubkeylist.append((reconstructed_secp192_point.x, reconstructed_secp192_point.y))

    return btc_pubkeylist, secp192_pubkeylist, data 

def is_on_curve(point, curve):
    x, y = point.x, point.y
    lhs = y * y % curve.field.p
    rhs = (x**3 + curve.a * x + curve.b) % curve.field.p
    return lhs == rhs

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


def array_to_point(curve, array):
    points = [] 
    for id in range(len(array)): 
        try :
            points.append(Point(curve, array[id][0], array[id][1]))
        except:
            raise("point not on curve")
    return points

def compact_object(chunks):
    b_x = 64  # TODO get from setup
    number_of_chunks = 3
    
    for id in range(number_of_chunks):
        if id == 0:
            result = chunks[id]
        else: 
            result += chunks[id] * (2 ** (id * b_x)) 
    return result

def aggregate_secp192r1_pubkeys(coords_list):
    # Combine the secp192r1 public keys into a single aggregated public key
    curve = registry.get_curve('secp192r1')
    agg_point = None
    for x, y in coords_list:
        point = Point(curve, x, y)
        if agg_point is None:
            agg_point = point
        else:
            agg_point += point
    return agg_point

def aggregate_btc_pubkeys(pubkeylist):
    # Combine the public keys into a single aggregated public key
    return PublicKey.combine_keys(pubkeylist)

def serialize_point(point):
    # Format as uncompressed point (04 + x + y)
    x_bytes = point.x.to_bytes(24, byteorder='big')  # 24 bytes for x secp192r1
    y_bytes = point.y.to_bytes(24, byteorder='big')  # 24 bytes for y secp192r1
    encoded_point = b'\x04' + x_bytes + y_bytes

    # Create public key from the encoded point using cryptography library
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP192R1(),
        encoded_point
    )

    # Get compressed format
    compressed_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962, # X9.62 standard for elliptic curve public keys
        format=serialization.PublicFormat.CompressedPoint # Compressed point format (02 or 03 prefix)
    )

    return compressed_bytes

def is_point_at_infinity_btc(pubkey):
    # Checks if the public key bytes are all zeros (invalid key)
    return pubkey.format() == b'\x00' * len(pubkey.format())

def is_generator_point_btc(pubkey):
    # secp256k1 generator point (compressed)
    generator_bytes = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    generator = PublicKey(generator_bytes)
    return pubkey.format() == generator.format()

def is_point_at_infinity_secp192r1(point):
    # Checks if the point is at infinity
    return point is None or (hasattr(point, "inf") and point.inf)

def is_generator_point_secp192r1(point):
    # Checks if the point is the generator of secp192r1
    curve = registry.get_curve('secp192r1')
    generator = curve.g
    return point.x == generator.x and point.y == generator.y


def main():
    pubkeybtc, pubkeyweak, proof_data = load_public_keys(PROOF_DIR)
    # Before aggregating any key, the proofs must be verified 
    proof_verification(proof_data) 
    # Will only aggregate values of the proofs are valid 
    agg_btc_point = aggregate_btc_pubkeys(pubkeybtc)
    print("Aggregated btc public key:", agg_btc_point.format().hex())

    agg_weak_point = aggregate_secp192r1_pubkeys(pubkeyweak)

    serial = serialize_point(agg_weak_point)
    print("Aggregated secp192r1 public key:", serial.hex())

    if is_point_at_infinity_btc(agg_btc_point):
        print("Error!!! Aggregated public btc key is point at infinity (private key = 0).")
    elif is_generator_point_btc(agg_btc_point):
        print("Error!!! Aggregated public btc key is generator (private key = 1).")
    else:
        print("Aggregated public btc key is valid.")

    if is_point_at_infinity_secp192r1(agg_weak_point):
        print("Error!!! Aggregated public secp192r1 key is point at infinity (private key = 0).")
        return
    elif is_generator_point_secp192r1(agg_weak_point):
        print("Error!!! Aggregated public secp192r1 key is generator (private key = 1).")
        return
    else:
        print("Aggregated public secp192r1 key is valid.")

if __name__ == "__main__":
    main()
