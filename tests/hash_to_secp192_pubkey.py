import hashlib
from tinyec import registry
from tinyec.ec import Point
from coincurve import PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# This script attempts to find a valid point on the secp192r1 curve using SHA-256 hashes of a public key.
# The objective is to get a public key for secp192r1 from a secp256k1 hashed and truncated public key.
# The idea is to truncate the 32 bytes to 24 bytes and then use the first 24 bytes as the x coordinate of the public key on secp192r1.
# Try then to do 1000 executions to see how many unvalid x's are generated.

# To check if the public key on secp192r1 is valid, we will use the equation of the curve finding a valid y coordinate. And then create a known public key to check, and also do a loop to find an invalid x value.
# Also try to find an invalid x value, that is, an x value that does not generate a valid y coordinate on the curve.

# Define the secp192r1 curve
curve = registry.get_curve('secp192r1')

priv1 = PrivateKey() # Generate a new private key secp256k1 (Bitcoin) with coincurve
pub1 = priv1.public_key # Get the public key from the private key
data_hex = pub1.format().hex()  # Format the public key to hex
data_bytes = bytes.fromhex(data_hex) # Convert hex to bytes
#print(data_hex)
hash_value = hashlib.sha256(data_bytes).digest() # Hash the public key to get a 32-byte hash, tested with https://emn178.github.io/online-tools/sha256.html
print("Initial SHA-256:", hash_value.hex())

# Get curve parameters (a, b and p) for
a = curve.a
b = curve.b
p = curve.field.p # secp192r1 prime field size


valid_point_found = False # Boolean to track if a valid point is found
hash_attempts = 1 # Counter for hash attempts

while not valid_point_found and hash_attempts < 100:  # Limit attempts to 100, the max tries reached when testing was 27
    x_bytes = hash_value[:24]  # Truncate to the first 24 bytes for secp192r1
    x_candidate = int.from_bytes(x_bytes, 'big') # Convert bytes to integer to get the x coordinate
    print("x_candidate before mod p:", x_candidate)

    # Make sure x is within field range of secp192r1
    x_candidate = x_candidate % p # Apply modulo p to ensure x is within the prime field size
    print("x_candidate after mod p:", x_candidate)

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
            print(f"Valid point found after {hash_attempts} hashes!")
            print(f"Point: x={point.x}, y={point.y}")
            print(x_candidate)
            valid_point_found = True
        except Exception as e:
            print(f"Error creating point: {e}")
            hash_value = hashlib.sha256(hash_value).digest()
            hash_attempts += 1
    else:
        # No valid y for this x, hash again
        hash_value = hashlib.sha256(hash_value).digest()
        hash_attempts += 1
        print(f"No valid point yet, attempts: {hash_attempts-1}")

if not valid_point_found:
    print(f"Failed to find valid point after {hash_attempts} hash attempts")


if valid_point_found:
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

    # Get uncompressed format
    uncompressed_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    print("Compressed public key:", compressed_bytes.hex())
    print("Uncompressed public key:", uncompressed_bytes.hex())


