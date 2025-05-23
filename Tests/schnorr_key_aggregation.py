from coincurve import PrivateKey, PublicKey
from bitcoinutils.keys import PublicKey as BitcoinPublicKey
from bitcoinutils.keys import PrivateKey as BitcoinPrivateKey
from bitcoinutils.setup import setup



#This version is for testing the Schnorr key aggregation, but is vulnerable to rogue key attacks. As far as I am concerned, for the purpose of the honeypot, rogue key attacks don't affect us, but it is important to be aware of them.
#The script of the protocol that will add all the pubkeys will need to ensure all pubkeys are valid and not repeated.
setup("testnet")

# Generate two private keys
priv1 = PrivateKey()
priv2 = PrivateKey()
# Generate a third private key
priv3 = PrivateKey()

print(priv1.secret.hex())
print(priv2.secret.hex())
print(priv3.secret.hex())


# Transform the privatekeys to integers
x1 = int.from_bytes(priv1.secret, 'big')
x2 = int.from_bytes(priv2.secret, 'big')

x3 = int.from_bytes(priv3.secret, 'big')

# Define the curve order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Calculate the aggregated secret key (without MuSig coefficients, UNSAFE for rogue key attacks, safe for the honeypot use as no multisig is used)
x_agg = (x1 + x2) % n
agg_secret = PrivateKey(x_agg.to_bytes(32, 'big'))

# Test with a third key
x_agg2 = (x1 + x2 + x3) % n
agg_secret2 = PrivateKey(x_agg2.to_bytes(32, 'big'))

# Test associative property
x_agg_associative = (x_agg + x3) % n
agg_secret_associative = PrivateKey(x_agg_associative.to_bytes(32, 'big'))

# Aggregate the public keys
pub1 = priv1.public_key
pub2 = priv2.public_key
agg_point = PublicKey.combine_keys([pub1, pub2])


# Test with a third key
pub3 = priv3.public_key
agg_point2 = PublicKey.combine_keys([pub1, pub2, pub3])

# Test associative property
agg_point_associative = PublicKey.combine_keys([agg_point, pub3])


# Verify that the public key derived from the aggregated secret matches
agg_from_secret = agg_secret.public_key

print("P1           =", pub1.format().hex())
print("P2           =", pub2.format().hex())
print("P1 + P2      =", agg_point.format().hex())
print("Agg from sec =", agg_from_secret.format().hex())
print("Match?       =", agg_point.format() == agg_from_secret.format())
print("-------------------------Third key-------------------------------------")
print("P3           =", pub3.format().hex())
print("P1 + P2 + P3 =", agg_point2.format().hex())
print("Agg from sec2 =", agg_secret2.public_key.format().hex())
print("Match?       =", agg_point2.format() == agg_secret2.public_key.format())
print("-------------------------Associative property---------------------------")
print("P1 + P2 + P3 =", agg_point_associative.format().hex())
print("Agg from sec3 =", agg_secret_associative.public_key.format().hex())
print("Match?       =", agg_point_associative.format() == agg_secret_associative.public_key.format())

print("-------------------------Bitcoinutils Pubkey transformation---------------------------")
# Transform public keys from coincurve to bitcoinutils
pub1hex = pub1.format().hex()
print("Pub1 hex:", pub1hex)
pub1btc = BitcoinPublicKey.from_hex(pub1hex)
print("Pub1 btc:", pub1btc.to_hex())
taprootpub = pub1btc.get_taproot_address()
print("Taproot:", taprootpub.to_string())

print("-------------------------Aggregated taproot---------------------------")
# Trasform aggregated public key from coincurve to bitcoinutils
agg_pointhex = agg_point2.format().hex()
print("Agg_point2 hex:", agg_pointhex)
agg_pointbtc = BitcoinPublicKey.from_hex(agg_pointhex)
print("Agg_point2 btc:", agg_pointbtc.to_hex())
taprootagg = agg_pointbtc.get_taproot_address()
print("Agg_point2 Taproot:", taprootagg.to_string())

print("-------------------------Bitcoinutils Privatekey transformation---------------------------")
# Transform the coincurve private keys to bitcoinutils private keys (this will be used for the QC protocol)
print(priv3.secret)
prova1 = BitcoinPrivateKey.from_bytes(priv3.secret)
print(prova1.to_bytes())

print("------------------------")
# Transform the aggregated private key to bitcoinutils private key to do a test tx
privagg = BitcoinPrivateKey.from_bytes(agg_secret2.secret)
print("\nPrivate key WIF:", privagg.to_wif(compressed=True))
