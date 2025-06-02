import hashlib
from tinyec import registry
from tinyec.ec import Point
from coincurve import PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# This is exactly the same code as hash_to_secp192_pubkey.py,
# but is designed to find invalid points on the secp192r1 curve, to check if the process works correctly when it fails to find a valid point.
# The only difference is that it forces the is_quadratic_residue to be True, so it will always try to create a Public Key, even if the x_candidate is not valid.

curve = registry.get_curve('secp192r1')

priv1 = PrivateKey()
pub1 = priv1.public_key
data_hex = pub1.format().hex()
data_bytes = bytes.fromhex(data_hex)
hash_value = hashlib.sha256(data_bytes).digest()
print("Initial SHA-256:", hash_value.hex())

# Get curve parameters
a = curve.a
b = curve.b
p = curve.field.p

valid_point_found = False
hash_attempts = 0

while not valid_point_found and hash_attempts < 100:
    x_bytes = hash_value[:24]  # Truncate to 24 bytes for secp192r1
    x_candidate = int.from_bytes(x_bytes, 'big')
    print("x_candidate before mod p:", x_candidate)

    # Make sure x is within field range
    x_candidate = x_candidate % p
    print("x_candidate after mod p:", x_candidate)

    # Calculate right side of equation: y² = x³ + ax + b (mod p)
    right_side = (pow(x_candidate, 3, p) + (a * x_candidate) % p + b) % p

    # Check if right_side has a square root in the field
    is_quadratic_residue = pow(right_side, (p - 1) // 2, p) == 1
    print("is_quadratic_residue:", is_quadratic_residue) # To debug
    is_quadratic_residue = True  # Force it to be true for testing
    if is_quadratic_residue:
        # Calculate y
        y = pow(right_side, (p + 1) // 4, p)

        try:
            # Create a point directly using the Point class
            point = Point(curve, x_candidate, y)
            print(f"Valid point found after {hash_attempts} additional hashes!")
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
        print(f"No valid point yet, attempts: {hash_attempts}")

if not valid_point_found:
    print(f"Failed to find valid point after {hash_attempts} hash attempts")


if valid_point_found:
    # Format as uncompressed point (04 + x + y)
    x_bytes = point.x.to_bytes(24, byteorder='big')  # 24 bytes for secp192r1
    y_bytes = point.y.to_bytes(24, byteorder='big')
    encoded_point = b'\x04' + x_bytes + y_bytes

    # Create public key from the encoded point
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP192R1(),
        encoded_point
    )

    # Get compressed format (the one that ECIES uses)
    compressed_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

    # Get uncompressed format
    uncompressed_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    print("Compressed public key:", compressed_bytes.hex())
    print("Uncompressed public key:", uncompressed_bytes.hex())


#Point (2639933361862055308264398563910473489496654943620523031277, 5719679107404590932056165366938160431209843841704063090358) is not on curve ""secp192r1" => y^2 = x^3 + 6277101735386680763835789423207666416083908700390324961276x + 2455155546008943817740293915197451784769108058161191238065 (mod 6277101735386680763835789423207666416083908700390324961279)"
#  warnings.warn("Point (%d, %d) is not on curve \"%s\"" % (self.x, self.y, self.curve))
#Traceback (most recent call last):
#    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
# ValueError: Invalid EC key.