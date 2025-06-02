import hashlib
from tinyec import registry
from tinyec.ec import Point
import time
import statistics
from coincurve import PrivateKey

# This script uses the same code as hash_to_secp192_pubkey.py but is designed to run multiple tests to check how many attempts it takes to find a valid point on the secp192r1 curve from a SHA-256 hash of a public key on the secp256k1 curve,
# and to gather statistics on the number of attempts required to find a valid point to ensure that the process works reliably across many samples.

# Global configuration for the test
MAX_HASH_ATTEMPTS = 10000  # Maximum number of hash attempts per data_hex
NUM_TEST_SAMPLES = 150000   # Number of different data_hex values to test

# Get the secp192r1 curve
curve = registry.get_curve('secp192r1')
a = curve.a
b = curve.b
p = curve.field.p


# Function to check if a point is on the curve
def find_valid_point(data_hex, max_attempts=MAX_HASH_ATTEMPTS):
    data_bytes = bytes.fromhex(data_hex)
    hash_value = hashlib.sha256(data_bytes).digest()

    hash_attempts = 1

    while hash_attempts < max_attempts:
        x_bytes = hash_value[:24]  # Truncate to 24 bytes for secp192r1
        x_candidate = int.from_bytes(x_bytes, 'big') % p

        # Calculate right side of equation: y² = x³ + ax + b (mod p)
        right_side = (pow(x_candidate, 3, p) + (a * x_candidate) % p + b) % p

        # Check if right_side has a square root in the field
        is_quadratic_residue = pow(right_side, (p - 1) // 2, p) == 1

        if is_quadratic_residue:
            # Calculate y
            y = pow(right_side, (p + 1) // 4, p)

            try:
                # Create a point directly using the Point class from tinyec
                point = Point(curve, x_candidate, y)
                return hash_attempts, point
            except Exception:
                # If there's an exception creating the point, continue trying
                pass

        # Hash again and increment attempts
        hash_value = hashlib.sha256(hash_value).digest()
        hash_attempts += 1

    return max_attempts, None


# Generate statistics for NUM_TEST_SAMPLES different data_hex values
def run_tests(num_tests=NUM_TEST_SAMPLES, max_attempts=MAX_HASH_ATTEMPTS):
    results = []
    successful = 0
    start_time = time.time()

    for i in range(num_tests):
        # Generate public key on secp256k1
        priv1 = PrivateKey()
        pub1 = priv1.public_key

        data_hex = pub1.format().hex()

        attempts, point = find_valid_point(data_hex, max_attempts)
        results.append(attempts)

        if point is not None:
            successful += 1

        # Print progress every 100 tests
        if (i + 1) % 100 == 0:
            elapsed = time.time() - start_time
            print(
                f"Completed {i + 1}/{num_tests} tests in {elapsed:.2f}s. Success rate: {successful / (i + 1) * 100:.2f}%")

    return results, successful


# Run the tests and show statistics
results, successful = run_tests()

# Calculate statistics
success_rate = successful / NUM_TEST_SAMPLES * 100
avg_attempts = statistics.mean(results)
median_attempts = statistics.median(results)
min_attempts = min(results)
max_attempts = max(results)

# Print results
print("\nTest Results:")
print(f"Maximum hash attempts per sample: {MAX_HASH_ATTEMPTS}")
print(f"Number of samples tested: {NUM_TEST_SAMPLES}")
print(f"Success rate: {success_rate:.2f}%")
print(f"Average hash attempts: {avg_attempts:.2f}")
print(f"Median hash attempts: {median_attempts}")
print(f"Min attempts: {min_attempts}")
print(f"Max attempts: {max_attempts}")

# Print distribution in ranges
ranges = [0, 1, 10, 100, 1000, MAX_HASH_ATTEMPTS]
for i in range(len(ranges) - 1):
    count = sum(1 for r in results if ranges[i] <= r < ranges[i + 1])
    print(f"Points found in {ranges[i]}-{ranges[i + 1] - 1} attempts: {count} ({count / (NUM_TEST_SAMPLES/100):.1f}%)")

# Points not found
not_found = sum(1 for r in results if r == MAX_HASH_ATTEMPTS)
print(f"Points not found within {MAX_HASH_ATTEMPTS} attempts: {not_found} ({not_found / (NUM_TEST_SAMPLES/100):.1f}%)")

# IN THIS RESULTS 0 ATTEMPTS MEANS THAT THE POINT WAS FOUND IN THE FIRST HASH, NOT THAT IT WAS NOT FOUND.
#--------------------------------------------------------------------------
#Test Results:
#Maximum hash attempts per sample: 10000
#Number of samples tested: 15000000 (Took 2 hours approximately)
#Success rate: 100.00%
#Average hash attempts: 1.00
#Median hash attempts: 0.0
#Min attempts: 0
#Max attempts: 27
#Points found in 0-0 attempts: 7500055 (50.0%)
#Points found in 1-9 attempts: 7485197 (49.9%)
#Points found in 10-99 attempts: 14748 (0.1%)
#Points found in 100-999 attempts: 0 (0.0%)
#Points found in 1000-9999 attempts: 0 (0.0%)
#Points not found within 10000 attempts: 0 (0.0%)

#--------------------------------------------------------------------------
#Test Results:
#Maximum hash attempts per sample: 10000
#Number of samples tested: 1500000
#Success rate: 100.00%
#Average hash attempts: 1.00
#Median hash attempts: 1.0
#Min attempts: 0
#Max attempts: 22
#Points found in 0-0 attempts: 749644 (50.0%)
#Points found in 1-9 attempts: 748846 (49.9%)
#Points found in 10-99 attempts: 1510 (0.1%)
#Points found in 100-999 attempts: 0 (0.0%)
#Points found in 1000-9999 attempts: 0 (0.0%)
#Points not found within 10000 attempts: 0 (0.0%)

#--------------------------------------------------------------------------
#Test Results:
#Maximum hash attempts per sample: 10000
#Number of samples tested: 150000
#Success rate: 100.00%
#Average hash attempts: 1.00
#Median hash attempts: 0.0
#Min attempts: 0
#Max attempts: 16
#Points found in 0-0 attempts: 75064 (50.0%)
#Points found in 1-9 attempts: 74787 (49.9%)
#Points found in 10-99 attempts: 149 (0.1%)
#Points found in 100-999 attempts: 0 (0.0%)
#Points found in 1000-9999 attempts: 0 (0.0%)
#Points not found within 10000 attempts: 0 (0.0%)

#--------------------------------------------------------------------------
#Test Results:
#Maximum hash attempts per sample: 10000
#Number of samples tested: 15000
#Success rate: 100.00%
#Average hash attempts: 1.00
#Median hash attempts: 0.0
#Min attempts: 0
#Max attempts: 13
#Points found in 0-0 attempts: 7551 (50.3%)
#Points found in 1-9 attempts: 7432 (49.5%)
#Points found in 10-99 attempts: 17 (0.1%)
#Points found in 100-999 attempts: 0 (0.0%)
#Points found in 1000-9999 attempts: 0 (0.0%)
#Points not found within 10000 attempts: 0 (0.0%)

#--------------------------------------------------------------------------
#Test Results:
#Maximum hash attempts per sample: 10000
#Number of samples tested: 1500
#Success rate: 100.00%
#Average hash attempts: 0.97
#Median hash attempts: 0.0
#Min attempts: 0
#Max attempts: 10
#Points found in 0-0 attempts: 786 (52.4%)
#Points found in 1-9 attempts: 713 (47.5%)
#Points found in 10-99 attempts: 1 (0.1%)
#Points found in 100-999 attempts: 0 (0.0%)
#Points found in 1000-9999 attempts: 0 (0.0%)
#Points not found within 10000 attempts: 0 (0.0%)

#--------------------------------------------------------------------------
#Test Results:
#Maximum hash attempts per sample: 10000
#Number of samples tested: 150
#Success rate: 100.00%
#Average hash attempts: 0.99
#Median hash attempts: 0.0
#Min attempts: 0
#Max attempts: 10
#Points found in 0-0 attempts: 77 (51.3%)
#Points found in 1-9 attempts: 72 (48.0%)
#Points found in 10-99 attempts: 1 (0.7%)
#Points found in 100-999 attempts: 0 (0.0%)
#Points found in 1000-9999 attempts: 0 (0.0%)
#Points not found within 10000 attempts: 0 (0.0%)

#--------------------------------------------------------------------------
#Test Results:
#Maximum hash attempts per sample: 10000
#Number of samples tested: 15
#Success rate: 100.00%
#Average hash attempts: 1.13
#Median hash attempts: 1
#Min attempts: 0
#Max attempts: 3
#Points found in 0-0 attempts: 5 (33.3%)
#Points found in 1-9 attempts: 10 (66.7%)
#Points found in 10-99 attempts: 0 (0.0%)
#Points found in 100-999 attempts: 0 (0.0%)
#Points found in 1000-9999 attempts: 0 (0.0%)
#Points not found within 10000 attempts: 0 (0.0%)