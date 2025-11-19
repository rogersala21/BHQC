import json
import os
from coincurve import PublicKey
import subprocess
from tinyec import registry
from tinyec.ec import Point
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import math 
from modules.dleqag import DLEQAG
from modules.dleq import DLEQ
from modules.curves import Secp192r1, Secp256k1
PROOF_DIR = "../outputs/participant/proofs"
OUTPUTS_DIR = "../outputs/coordinator/key_agg_output"


number_of_entities = 64
number_of_chunks = 3
b_x = 64 
b_f = 3
b_c = 124
b_g = 192


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
                        p_256_points = Secp256k1.array_to_point(btc_pubkey_chunks)
                        # Compact_object to reconstruct
                        reconstructed_btc_point = compact_object(p_256_points)
                        
                        try:
                            pubkey_btc = PublicKey.from_point(reconstructed_btc_point.x, reconstructed_btc_point.y)
                            btc_pubkeylist.append(pubkey_btc)
                        except Exception as e:
                            print(f"Error creating BTC PublicKey: {e}")


                        # Convert secp192r1 to Point object
                        p_192_points = Secp192r1.array_to_point(secp192_pubkey_chunks)
                        # Compact_object to reconstruct
                        reconstructed_secp192_point = compact_object(p_192_points)
                        
                        secp192_pubkeylist.append((reconstructed_secp192_point.x, reconstructed_secp192_point.y))

    return btc_pubkeylist, secp192_pubkeylist, data 


def proof_verification(proof):

#   Verification of the proofs for discrete logarithm equality across groups
    dleqag_inst = DLEQAG(b_x, b_f, b_c, number_of_chunks, Secp192r1.field.n >> 6, Secp256k1, Secp192r1)
    dleqag_inst.proof_verification(proof)

    C_256 = Secp256k1.array_to_point(proof["C_256"])
    p_256 = Secp256k1.array_to_point(proof["p_256"])
    C_192 = Secp192r1.array_to_point(proof["C_192"])
    p_192 = Secp192r1.array_to_point(proof["p_192"])
    p_256_proof = compact_object(p_256)
    p_192_proof = compact_object(p_192)
    C_256_proof = compact_object(C_256)
    C_192_proof = compact_object(C_192)
#   Verification of the proofs for discrete logarithm equality of public key and commitments on SECP256K1
    dleq_inst_secp256k1 = DLEQ(Secp256k1)
    dleq_inst_secp256k1.proof_verification(proof["dleq_256"], C_256_proof, p_256_proof)
#   Verification of the proofs for discrete logarithm equality of public key and commitments on SECP192r1
    dleq_inst_secp192r1 = DLEQ(Secp192r1)
    dleq_inst_secp192r1.proof_verification(proof["dleq_192"], C_192_proof, p_192_proof)

def range_proof_verification(b_x, number_of_chunks, over_flow_bits):
    # node bulletproof_gen.js verify ../../../outputs/participant/proofs/proof0.json 64
    for index in range(number_of_chunks):
        result = subprocess.run(
        ["node", "./modules/bulletproofs/bulletproof.js", "verify", f"../../../outputs/participant/proofs/proof{index}.json", str( b_x - int(index == number_of_chunks -1) * over_flow_bits)],  # pass arguments
        capture_output=True,
        text=True
        )
    print("Range proofs verified")


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
    over_flow_bits = math.log2(number_of_entities)
    range_proof_verification(b_x, number_of_chunks, over_flow_bits)
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
