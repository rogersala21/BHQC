from coincurve import PrivateKey, PublicKey
from bitcoinutils.keys import PublicKey as BitcoinPublicKey
from bitcoinutils.keys import PrivateKey as BitcoinPrivateKey
from bitcoinutils.setup import setup
import time

setup("testnet")
# Define the curve order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

print("---------------------------")
print("loop aggregating 1000 key pairs and doing a signature")
print("\n--------------------------------------\n")

# Message to sign
message = "Schnorr key aggregation test"

print("\nStarting 1000 key aggregation tests...")
start_time = time.time()
success_count = 0

for i in range(1000):
    # Generate two private keys with coincurve library
    priv1 = PrivateKey()
    priv2 = PrivateKey()

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
        print(f"Error in iteration {i+1}: Public key mismatch")
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
            #priv_agg_btc= BitcoinPrivateKey.from_bytes(priv1.secret)

        # Sign and verify
        signature = priv_agg_btc.sign_message(message)
        assert signature is not None
        if BitcoinPublicKey.verify_message(address.to_string(), signature, message):
            success_count += 1
        else:
            print(f"Signature verification failed in iteration {i+1}")

    except Exception as e:
        print(f"Error in iteration {i+1}: {e}")

    # Print progress every 100 iterations
    if (i + 1) % 100 == 0:
        print(f"Completed {i+1} iterations. Success rate: {success_count/(i+1)*100:.2f}%")

total_time = time.time() - start_time
print(f"\nTest completed in {total_time:.2f} seconds")
print(f"Total success: {success_count}/1000 ({success_count/10:.2f}%)")
print(f"Average time per iteration: {total_time/1000:.4f} seconds")


print("-------------------------")
print("-------------------------")
print("\nStarting 1000 three-key aggregation tests...")
start_time = time.time()
success_count = 0

for i in range(1000):
    # Generate three private keys with coincurve library
    priv1 = PrivateKey()
    priv2 = PrivateKey()
    priv3 = PrivateKey()

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
        print(f"Error in iteration {i+1}: Public key mismatch")
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
            #priv_agg_btc= BitcoinPrivateKey.from_bytes(priv1.secret)

        # Sign and verify
        signature = priv_agg_btc.sign_message(message)
        assert signature is not None
        if BitcoinPublicKey.verify_message(address.to_string(), signature, message):
            success_count += 1
        else:
            print(f"Signature verification failed in iteration {i+1}")

    except Exception as e:
        print(f"Error in iteration {i+1}: {e}")

    # Print progress every 100 iterations
    if (i + 1) % 100 == 0:
        print(f"Completed {i+1} iterations. Success rate: {success_count/(i+1)*100:.2f}%")

total_time = time.time() - start_time
print(f"\nThree-key test completed in {total_time:.2f} seconds")
print(f"Total success: {success_count}/1000 ({success_count/10:.2f}%)")
print(f"Average time per iteration: {total_time/1000:.4f} seconds")



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

#Test completed in 75.08 seconds
#Total success: 1000/1000 (100.00%)
#Average time per iteration: 0.0751 seconds
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

#Three-key test completed in 74.71 seconds
#Total success: 1000/1000 (100.00%)
#Average time per iteration: 0.0747 seconds



#---------------------------
#loop aggregating 10000 key pairs and doing a signature

#--------------------------------------


#Starting 10000 key aggregation tests...
#Completed 1000 iterations. Success rate: 100.00%
#Completed 2000 iterations. Success rate: 100.00%
#Completed 3000 iterations. Success rate: 100.00%
#Completed 4000 iterations. Success rate: 100.00%
#Completed 5000 iterations. Success rate: 100.00%
#Completed 6000 iterations. Success rate: 100.00%
#Completed 7000 iterations. Success rate: 100.00%
#Completed 8000 iterations. Success rate: 100.00%
#Completed 9000 iterations. Success rate: 100.00%
#Completed 10000 iterations. Success rate: 100.00%

#Test completed in 743.93 seconds
#Total success: 10000/10000 (100.00%)
#Average time per iteration: 0.0744 seconds
#-------------------------
#-------------------------

#Starting 10000 three-key aggregation tests...
#Completed 1000 iterations. Success rate: 100.00%
#Completed 2000 iterations. Success rate: 100.00%
#Completed 3000 iterations. Success rate: 100.00%
#Completed 4000 iterations. Success rate: 100.00%
#Completed 5000 iterations. Success rate: 100.00%
#Completed 6000 iterations. Success rate: 100.00%
#Completed 7000 iterations. Success rate: 100.00%
#Completed 8000 iterations. Success rate: 100.00%
#Completed 9000 iterations. Success rate: 100.00%
#Completed 10000 iterations. Success rate: 100.00%

#Three-key test completed in 761.64 seconds
#Total success: 10000/10000 (100.00%)
#Average time per iteration: 0.0762 seconds