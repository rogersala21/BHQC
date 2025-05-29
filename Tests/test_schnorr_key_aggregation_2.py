from coincurve import PrivateKey, PublicKey
from bitcoinutils.keys import PublicKey as BitcoinPublicKey
from bitcoinutils.keys import PrivateKey as BitcoinPrivateKey
from bitcoinutils.setup import setup
import time

# This test is the same as test_schnorr_key_aggregation.py but with a final aggregation of all keys generated in the previous tests to test the correctness of the aggregation process when a large number of keys are aggregated together.

setup("testnet")
# Define the curve order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

print("---------------------------")
print("loop aggregating 1000 key pairs and doing a signature")
print("\n--------------------------------------\n")

# Message to sign
message = "Schnorr key aggregation test"

# Lists to store all keys for later aggregation
all_priv_keys_test1 = []
all_pub_keys_test1 = []

print("\nStarting 1000 key aggregation tests...")
start_time = time.time()
success_count = 0

for i in range(1000):
    # Generate two private keys with coincurve library
    priv1 = PrivateKey()
    priv2 = PrivateKey()

    # Save the keys for later large aggregation
    all_pub_keys_test1.append(priv1.public_key)
    all_pub_keys_test1.append(priv2.public_key)
    # Test 1 each 100 iterations wrong key to simulate a failure
    #if i % 100 == 0:
        #priv1 = priv2
    all_priv_keys_test1.append(priv1)
    all_priv_keys_test1.append(priv2)


    # Transform the privatekeys to integers
    x1 = int.from_bytes(priv1.secret, 'big')
    x2 = int.from_bytes(priv2.secret, 'big')

    # Calculate the aggregated secret key
    x_agg = (x1 + x2) % n
    agg_secret = PrivateKey(x_agg.to_bytes(32, 'big'))

    # Get public keys and aggregate them
    pub1 = priv1.public_key
    pub2 = priv2.public_key
    agg_pub = PublicKey.combine_keys([pub1, pub2])

    # Verify that the public key derived from the aggregated secret matches
    agg_from_secret = agg_secret.public_key

    if agg_pub.format() != agg_from_secret.format():
        print(f"Error in iteration {i + 1}: Public key mismatch")
        continue

    try:
        # Transform to bitcoinutils
        agg_pub_hex = agg_pub.format().hex()
        agg_pub_btc = BitcoinPublicKey.from_hex(agg_pub_hex)

        # Transform private key to bitcoinutils
        priv_agg_btc = BitcoinPrivateKey.from_bytes(agg_secret.secret)

        # Get address
        address = agg_pub_btc.get_address()

        # Test 1 each 100 iterations wrong key to simulate a failure
        #if i % 100 == 0:
            #priv_agg_btc = BitcoinPrivateKey.from_bytes(priv1.secret)

        # Sign and verify
        signature = priv_agg_btc.sign_message(message)
        assert signature is not None
        if BitcoinPublicKey.verify_message(address.to_string(), signature, message):
            success_count += 1
        else:
            print(f"Signature verification failed in iteration {i + 1}")

    except Exception as e:
        print(f"Error in iteration {i + 1}: {e}")

    # Print progress every 100 iterations
    if (i + 1) % 100 == 0:
        print(f"Completed {i + 1} iterations. Success rate: {success_count / (i + 1) * 100:.2f}%")

total_time = time.time() - start_time
print(f"\nTest completed in {total_time:.2f} seconds")
print(f"Total success: {success_count}/1000 ({success_count / 10:.2f}%)")
print(f"Average time per iteration: {total_time / 1000:.4f} seconds")



# Same test but with three keys to test the correctness of the aggregation process when a large number of keys are aggregated together.
print("-------------------------")
print("-------------------------")
print("\nStarting 1000 three-key aggregation tests...")

# Lists to store all keys for later aggregation
all_priv_keys_test2 = []
all_pub_keys_test2 = []

start_time = time.time()
success_count = 0

for i in range(1000):
    # Generate three private keys with coincurve library
    priv1 = PrivateKey()
    priv2 = PrivateKey()
    priv3 = PrivateKey()

    # Save the keys for later large aggregation
    all_pub_keys_test2.append(priv1.public_key)
    all_pub_keys_test2.append(priv2.public_key)
    all_pub_keys_test2.append(priv3.public_key)
    # Test 1 each 100 iterations wrong key to simulate a failure
    #if i % 100 == 0:
        #priv1 = priv2
    all_priv_keys_test2.append(priv1)
    all_priv_keys_test2.append(priv2)
    all_priv_keys_test2.append(priv3)


    # Transform the privatekeys to integers
    x1 = int.from_bytes(priv1.secret, 'big')
    x2 = int.from_bytes(priv2.secret, 'big')
    x3 = int.from_bytes(priv3.secret, 'big')

    # Calculate the aggregated secret key for 3 keys
    x_agg = (x1 + x2 + x3) % n
    agg_secret = PrivateKey(x_agg.to_bytes(32, 'big'))

    # Get public keys and aggregate them
    pub1 = priv1.public_key
    pub2 = priv2.public_key
    pub3 = priv3.public_key
    agg_pub = PublicKey.combine_keys([pub1, pub2, pub3])

    # Verify that the public key derived from the aggregated secret matches
    agg_from_secret = agg_secret.public_key

    if agg_pub.format() != agg_from_secret.format():
        print(f"Error in iteration {i + 1}: Public key mismatch")
        continue

    try:
        # Transform to bitcoinutils
        agg_pub_hex = agg_pub.format().hex()
        agg_pub_btc = BitcoinPublicKey.from_hex(agg_pub_hex)

        # Transform private key to bitcoinutils
        priv_agg_btc = BitcoinPrivateKey.from_bytes(agg_secret.secret)

        # Get address
        address = agg_pub_btc.get_address()
        # Test 1 each 100 iterations wrong key to simulate a failure
        #if i % 100 == 0:
            #priv_agg_btc = BitcoinPrivateKey.from_bytes(priv1.secret)

        # Sign and verify
        signature = priv_agg_btc.sign_message(message)
        assert signature is not None
        if BitcoinPublicKey.verify_message(address.to_string(), signature, message):
            success_count += 1
        else:
            print(f"Signature verification failed in iteration {i + 1}")

    except Exception as e:
        print(f"Error in iteration {i + 1}: {e}")

    # Print progress every 100 iterations
    if (i + 1) % 100 == 0:
        print(f"Completed {i + 1} iterations. Success rate: {success_count / (i + 1) * 100:.2f}%")

total_time = time.time() - start_time
print(f"\nThree-key test completed in {total_time:.2f} seconds")
print(f"Total success: {success_count}/1000 ({success_count / 10:.2f}%)")
print(f"Average time per iteration: {total_time / 1000:.4f} seconds")



# Perform large aggregation for 2000 keys list (from test 1)

print("\n-------------------------")
print("Large Key Aggregation Tests")
print("-------------------------")

print("\nAggregating 2000 keys from test 1...")
start_time = time.time()

# Aggregate all private keys (integer sum)
agg_x = 0
for priv in all_priv_keys_test1:
    x = int.from_bytes(priv.secret, 'big')
    agg_x = (agg_x + x) % n

# Create private key from aggregate
agg_priv_key = PrivateKey(agg_x.to_bytes(32, 'big'))
agg_pub_key = agg_priv_key.public_key

# Combine all public keys
combined_pub_key = PublicKey.combine_keys(all_pub_keys_test1)

# Verify that keys match
if agg_pub_key.format() != combined_pub_key.format():
    print("Error: Public key mismatch in 2000-key aggregation!")
else:
    print("Public key verification successful for 2000-key aggregation")

try:
    # Transform to bitcoinutils
    agg_pub_hex = combined_pub_key.format().hex()
    agg_pub_btc = BitcoinPublicKey.from_hex(agg_pub_hex)

    # Transform private key to bitcoinutils
    priv_agg_btc = BitcoinPrivateKey.from_bytes(agg_priv_key.secret)

    # Get address
    address = agg_pub_btc.get_address()

    # Sign and verify
    signature = priv_agg_btc.sign_message(message)
    if BitcoinPublicKey.verify_message(address.to_string(), signature, message):
        print("Signature verification successful for 2000-key aggregation")
    else:
        print("Signature verification failed for 2000-key aggregation")

except Exception as e:
    print(f"Error in 2000-key aggregation: {e}")

total_time = time.time() - start_time
print(f"2000-key aggregation completed in {total_time:.2f} seconds")



# Perform large aggregation for 3000 keys (from test 2)
print("\nAggregating 3000 keys from test 2...")
start_time = time.time()

# Aggregate all private keys (integer sum)
agg_x = 0
for priv in all_priv_keys_test2:
    x = int.from_bytes(priv.secret, 'big')
    agg_x = (agg_x + x) % n

# Create private key from aggregate
agg_priv_key = PrivateKey(agg_x.to_bytes(32, 'big'))
agg_pub_key = agg_priv_key.public_key

# Combine all public keys
combined_pub_key = PublicKey.combine_keys(all_pub_keys_test2)

# Verify that keys match
if agg_pub_key.format() != combined_pub_key.format():
    print("Error: Public key mismatch in 3000-key aggregation!")
else:
    print("Public key verification successful for 3000-key aggregation")

try:
    # Transform to bitcoinutils
    agg_pub_hex = combined_pub_key.format().hex()
    agg_pub_btc = BitcoinPublicKey.from_hex(agg_pub_hex)

    # Transform private key to bitcoinutils
    priv_agg_btc = BitcoinPrivateKey.from_bytes(agg_priv_key.secret)

    # Get address
    address = agg_pub_btc.get_address()

    # Sign and verify
    signature = priv_agg_btc.sign_message(message)
    if BitcoinPublicKey.verify_message(address.to_string(), signature, message):
        print("Signature verification successful for 3000-key aggregation")
    else:
        print("Signature verification failed for 3000-key aggregation")

except Exception as e:
    print(f"Error in 3000-key aggregation: {e}")

total_time = time.time() - start_time
print(f"3000-key aggregation completed in {total_time:.2f} seconds")



#---------------------------
#loop aggregating 1000 key pairs and doing a signature

#--------------------------------------


#Starting 1000 key aggregation tests...
#Completed 100 iterations. Success rate: 100.00%
#Completed 200 iterations. Success rate: 100.00%
#Completed 300 iterations. Success rate: 100.00%
#Completed 400 iterations. Success rate: 100.00%
#Completed 500 iterations. Success rate: 100.00%
#Completed 600 iterations. Success rate: 100.00%
#Completed 700 iterations. Success rate: 100.00%
#Completed 800 iterations. Success rate: 100.00%
#Completed 900 iterations. Success rate: 100.00%
#Completed 1000 iterations. Success rate: 100.00%

#Test completed in 74.38 seconds
#Total success: 1000/1000 (100.00%)
#Average time per iteration: 0.0744 seconds
#-------------------------
#-------------------------

#Starting 1000 three-key aggregation tests...
#Completed 100 iterations. Success rate: 100.00%
#Completed 200 iterations. Success rate: 100.00%
#Completed 300 iterations. Success rate: 100.00%
#Completed 400 iterations. Success rate: 100.00%
#Completed 500 iterations. Success rate: 100.00%
#Completed 600 iterations. Success rate: 100.00%
#Completed 700 iterations. Success rate: 100.00%
#Completed 800 iterations. Success rate: 100.00%
#Completed 900 iterations. Success rate: 100.00%
#Completed 1000 iterations. Success rate: 100.00%

#Three-key test completed in 74.09 seconds
#Total success: 1000/1000 (100.00%)
#Average time per iteration: 0.0741 seconds


# This is the result of the test set, which aggregates 2000 keys and does a signature test to check the correctness of the aggregation in a large scale.
# Then it aggregates 3000 keys and does a signature test to check the correctness of the aggregation in a large scale.
# As can be seen, the public key verification and signature verification are successful for both aggregations.
#-------------------------
#Large Key Aggregation Tests
#-------------------------

#Aggregating 2000 keys from test 1...
#Public key verification successful for 2000-key aggregation
#Signature verification successful for 2000-key aggregation
#2000-key aggregation completed in 0.06 seconds

#Aggregating 3000 keys from test 2...
#Public key verification successful for 3000-key aggregation
#Signature verification successful for 3000-key aggregation
#3000-key aggregation completed in 0.06 seconds