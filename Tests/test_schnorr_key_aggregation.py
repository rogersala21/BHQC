from coincurve import PrivateKey, PublicKey

#This version is for testing the Schnorr key aggregation, but is vulnerable to rogue key attacks.

# Generate two private keys
priv1 = PrivateKey()
priv2 = PrivateKey()

print(priv1.secret.hex())
print(priv2.secret.hex())

# Transform the privatekeys to integers
x1 = int.from_bytes(priv1.secret, 'big')
x2 = int.from_bytes(priv2.secret, 'big')

# Define the curve order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Calculate the aggregated secret key (without MuSig coefficients, UNSAFE)
x_agg = (x1 + x2) % n
agg_secret = PrivateKey(x_agg.to_bytes(32, 'big'))

# Aggregate the public keys
pub1 = priv1.public_key
pub2 = priv2.public_key
agg_point = PublicKey.combine_keys([pub1, pub2])

# Verify that the public key derived from the aggregated secret matches
agg_from_secret = agg_secret.public_key

print("P1           =", pub1.format().hex())
print("P2           =", pub2.format().hex())
print("P1 + P2      =", agg_point.format().hex())
print("Agg from sec =", agg_from_secret.format().hex())
print("Match?       =", agg_point.format() == agg_from_secret.format())
