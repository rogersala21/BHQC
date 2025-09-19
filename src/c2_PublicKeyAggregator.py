import json
import os
from coincurve import PublicKey
from tinyec import registry
from tinyec.ec import Point
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

PROOF_DIR = "../outputs/participant/proofs"
OUTPUTS_DIR = "../outputs/coordinator/key_agg_output"

def load_public_keys(proof_dir):
    # We iterate through all public key files in the specified directory and create a list of PublicKey objects.
    btc_pubkeylist = []
    secp192_pubkeylist = []
    for filename in os.listdir(proof_dir):
        file_path = os.path.join(proof_dir, filename)
        if os.path.isfile(file_path) and filename.startswith("proof_") and filename.endswith(".json"):
            with open(file_path, "r") as f:
                data = json.load(f)
                btc_pubkey_coords = data.get("public_key_btc") # CHANGE FOR WHATEVER WE USE IN THE PROOF JSON
                secp192_pubkey_coords = data.get("enc_point_k") # CHANGE FOR WHATEVER WE USE IN THE PROOF JSON
                if btc_pubkey_coords is None and secp192_pubkey_coords is None:
                    print(f"Warning: No public_key found in {filename}")
                    continue
                # Create PublicKey object from coordinates
                if btc_pubkey_coords is not None:
                    x = btc_pubkey_coords[0]
                    y = btc_pubkey_coords[1]
                    pubkey_btc = PublicKey.from_point(x, y)
                    btc_pubkeylist.append(pubkey_btc)
                # Create PublicKey coordinates list
                if secp192_pubkey_coords is not None:
                    x = secp192_pubkey_coords[0]
                    y = secp192_pubkey_coords[1]
                    secp192_pubkeylist.append((x, y))

    print("SECP192 Public Key List:")
    for pk_bytes in secp192_pubkeylist:
        print(pk_bytes)
    return btc_pubkeylist, secp192_pubkeylist

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
    pubkeybtc, pubkeyweak = load_public_keys(PROOF_DIR)

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
