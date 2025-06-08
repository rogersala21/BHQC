import os
from coincurve import PublicKey
import hashlib
from tinyec import registry
from tinyec.ec import Point
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

PUBKEY_DIR = "../outputs/coordinator/key_agg_input"
OUTPUTS_DIR = "../outputs/coordinator/key_agg_output"

def load_public_keys(pubkey_dir):
    # We iterate through all public key files in the specified directory and create a list of PublicKey objects.
    pubkeylist = []
    for filename in os.listdir(pubkey_dir):
        file_path = os.path.join(pubkey_dir, filename)
        if os.path.isfile(file_path) and filename.endswith(".txt"):
            with open(file_path, "r") as f:
                content = f.read()
                pubkey_bytes = bytes.fromhex(content)
                pubkey_cc = PublicKey(pubkey_bytes)
                pubkeylist.append(pubkey_cc)
    return pubkeylist

def aggregate_public_keys(pubkeylist):
    # Combine the public keys into a single aggregated public key
    return PublicKey.combine_keys(pubkeylist)

def hash_public_key(agg_point):
    # Convert the aggregated public key to bytes to hash it
    agg_point_hex = agg_point.format().hex()
    agg_point_bytes = bytes.fromhex(agg_point_hex)
    # Hash the aggregated public key using SHA-256
    hash_value = hashlib.sha256(agg_point_bytes).digest()
    #print(hash_value.hex())
    return hash_value

def find_valid_curve_point(hash_value, curve, max_attempts=100):
    # Get curve parameters (a, b and p) for secp192r1
    a = curve.a
    b = curve.b
    p = curve.field.p # secp192r1 prime field size

    valid_point_found = False # Boolean to track if a valid point is found
    hash_attempts = 1 # Counter for hash attempts

    while not valid_point_found and hash_attempts < max_attempts:
        x_bytes = hash_value[:24]  # Truncate to the first 24 bytes for secp192r1
        x_candidate = int.from_bytes(x_bytes, 'big') # Convert bytes to integer to get the x coordinate
        #print("x_candidate before mod p:", x_candidate)

        # Make sure x is within field range of secp192r1
        x_candidate = x_candidate % p # Apply modulo p to ensure x is within the prime field size
        #print("x_candidate after mod p:", x_candidate)

        # Calculate right side of equation: y² = x³ + ax + b (mod p)
        right_side = (pow(x_candidate, 3, p) + (a * x_candidate) % p + b) % p # Here we calculate the right side of the elliptic curve equation to find y²

        # Check if y²(right_side) has a square root in the field, which means we can find a valid y coordinate for the given x
        # This happens in elliptic curves because not all x values will yield a valid y value on the curve,
        # as finite fields only have a limited set of numbers that have square roots and complex numbers do not exist in finite fields.
        # This uses Euler's criterion to check if right_side is a quadratic residue modulo p, and therefore, a square root exists.
        is_quadratic_residue = pow(right_side, (p - 1) // 2, p) == 1

        if is_quadratic_residue:
            # Calculate y doing the modular square root
            y = pow(right_side, (p + 1) // 4, p)

            try:
                # Create a point directly using the Point class from tinyec
                point = Point(curve, x_candidate, y)
                #print(f"Valid point found after {hash_attempts} hashes!")
                #print(f"Hash value: {hash_value.hex()}")
                #print(f"Point: x={point.x}, y={point.y}")
                #print(x_candidate)
                valid_point_found = True
                return point, hash_attempts
            except Exception as e:
                print(f"Error creating point: {e}")
                hash_value = hashlib.sha256(hash_value).digest()
                hash_attempts += 1
        else:
            # No valid y for this x, hash again
            hash_value = hashlib.sha256(hash_value).digest()
            hash_attempts += 1
            #print(f"No valid point yet, attempts: {hash_attempts-1}")

    print(f"Failed to find valid point after {hash_attempts} hash attempts")
    return None, hash_attempts

def serialize_point(point):
    # Format as uncompressed point (04 + x + y)
    x_bytes = point.x.to_bytes(24, byteorder='big')  # 24 bytes for x secp192r1
    y_bytes = point.y.to_bytes(24, byteorder='big')  # 24 bytes for y secp192r1
    encoded_point = b'\x04' + x_bytes + y_bytes

    # Create public key from the encoded point using cryptography library to match the format used in ECIES script
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP192R1(),
        encoded_point
    )

    # Get compressed format (the one that ECIES script uses)
    compressed_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962, # X9.62 standard for elliptic curve public keys
        format=serialization.PublicFormat.CompressedPoint # Compressed point format (02 or 03 prefix)
    )


    #print("Compressed public key:", compressed_bytes.hex())
    return compressed_bytes

def is_point_at_infinity(pubkey):
    # Checks if the public key bytes are all zeros (invalid key)
    return pubkey.format() == b'\x00' * len(pubkey.format())

def is_generator_point(pubkey):
    # secp256k1 generator point (compressed)
    generator_bytes = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    generator = PublicKey(generator_bytes)
    return pubkey.format() == generator.format()

def main():
    pubkeylist = load_public_keys(PUBKEY_DIR)
    #print("List of public keys:", [p.format().hex() for p in pubkeylist])

    agg_point = aggregate_public_keys(pubkeylist)
    #print("Aggregated public key:", agg_point.format().hex())

    #from coincurve import PrivateKey
    #priv_key = PrivateKey(b'\x00' * 31 + b'\x01')
    #pub_key = priv_key.public_key
    #agg_point = pub_key

    #from coincurve import PrivateKey
    #priv_key = PrivateKey(b'\x00' * 31 + b'\x00')
    #pub_key = priv_key.public_key
    #agg_point = pub_key

    if is_point_at_infinity(agg_point):
        print("Error!!! Aggregated public key is point at infinity (private key = 0).")
        return
    elif is_generator_point(agg_point):
        print("Error!!! Aggregated public key is generator (private key = 1).")
        return
    else:
        print("Aggregated public key is valid.")


    hash_value = hash_public_key(agg_point)

    curve = registry.get_curve('secp192r1')
    point, attempts = find_valid_curve_point(hash_value, curve)

    if point:
        secp192r1_public_key = serialize_point(point)
        out_path = os.path.join(OUTPUTS_DIR, "aggregation_output.txt")
        with open(out_path, "w") as out_file:
            out_file.write(agg_point.format().hex() + '\n')
            out_file.write(str(attempts) + '\n')
            out_file.write(secp192r1_public_key.hex())
        print("Public key aggregation completed successfully and saved to", out_path)
    else:
        print("No valid curve point found.")



if __name__ == "__main__":
    main()
