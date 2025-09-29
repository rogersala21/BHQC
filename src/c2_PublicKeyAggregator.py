import json
import os
from coincurve import PublicKey
from tinyec import registry
from tinyec.ec import Point
from tinyec.ec import SubGroup, Curve
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

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

def load_public_keys(proof_dir):
    btc_pubkeylist = []
    secp192_pubkeylist = []
    for filename in os.listdir(proof_dir):
        file_path = os.path.join(proof_dir, filename)
        if os.path.isfile(file_path) and filename.startswith("proof_") and filename.endswith(".json"):
            with open(file_path, "r") as f:
                data = json.load(f)

                # Convert chunks to Point objects
                btc_pubkey_chunks = data.get("p_256")
                if btc_pubkey_chunks is not None and len(btc_pubkey_chunks) == 3:
                    # Convert to Point
                    p_256_points = array_to_point(btc_curve, btc_pubkey_chunks)
                    # Compact_object to reconstruct
                    reconstructed_btc_point = compact_object(p_256_points)
                    
                    try:
                        pubkey_btc = PublicKey.from_point(reconstructed_btc_point.x, reconstructed_btc_point.y)
                        btc_pubkeylist.append(pubkey_btc)
                    except Exception as e:
                        print(f"Error creating BTC PublicKey: {e}")

                secp192_pubkey_chunks = data.get("p_192")
                if secp192_pubkey_chunks is not None and len(secp192_pubkey_chunks) == 3:
                    # Convert to Point object 
                    p_192_points = array_to_point(weak_curve, secp192_pubkey_chunks)
                    # Compact_object to reconstruct
                    reconstructed_secp192_point = compact_object(p_192_points)
                    
                    secp192_pubkeylist.append((reconstructed_secp192_point.x, reconstructed_secp192_point.y))

    return btc_pubkeylist, secp192_pubkeylist

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

def reconstruct_point_from_chunks(point_chunks, curve):
    result_point = None
    
    for i, chunk in enumerate(point_chunks):
        x, y = chunk[0], chunk[1]
        
        try:
            # Create point from chunk coordinates
            point = Point(curve, x, y)
            
            # Add to result
            if result_point is None:
                result_point = point
            else:
                result_point = result_point + point
                
        except Exception as e:
            print(f"Error processing chunk {i}: {e}")
            return None
    
    return result_point


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
