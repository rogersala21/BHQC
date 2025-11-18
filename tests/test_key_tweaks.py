from bitcoinutils.setup import setup
from bitcoinutils.keys import PublicKey, PrivateKey
from bitcoinutils.utils import tweak_taproot_pubkey, tweak_taproot_privkey, tagged_hash

# Initialize Bitcoin testnet
setup("testnet")

#### PUBLIC KEY TWEAKING FOR TAPROOT ####

# Define the custom tweak message
commitment = "This is a test commitment for taproot pubkey tweak"
commitment_bytes = commitment.encode('utf-8')

# Load internal public key
internal_pubkey = PublicKey("PUBKEY HERE")
internal_pubkey_bytes = internal_pubkey.to_bytes()

# Generate the tweak using tagged_hash
# Correct argument order: (data, tag)
# Tagged hash is used to create a unique tweak based on the internal public key and the commitment message
tap_tweak = tagged_hash(internal_pubkey_bytes + commitment_bytes, "TapTweak") # We ensure that the tweak is derived from the internal public key and the commitment message (unique)
# TapTweak is a tag added to the data before hashing, used for protocol-specific tweaks, without tagging, if you hash the same data in different contexts, the output hashes could collide or be misinterpreted.
print("Taproot tweak (hex):", tap_tweak.hex())
tweak_int = int.from_bytes(tap_tweak, 'big')

# Tweak the internal public key
tweaked_pubkey_bytes, is_odd = tweak_taproot_pubkey(internal_pubkey_bytes, tweak_int) # Returns tweaked public key bytes and whether the y-coordinate is odd or even
prefix = b'\x03' if is_odd else b'\x02' # Add prefix for compressed format
compressed_key = prefix + tweaked_pubkey_bytes
tweaked_pubkey_hex = compressed_key.hex()

# Create tweaked public key and taproot address
tweaked_pubkey = PublicKey.from_hex(tweaked_pubkey_hex)
taproot_address = tweaked_pubkey.get_taproot_address()
print("Taproot address from tweaked public key:", taproot_address.to_string())


#### PRIVATE KEY TWEAKING FOR TAPROOT ####

# Load internal private key WIF and apply same tweak
priv = PrivateKey("PRIVATE KEY WIF HERE")  # This will be the one that is calculated once a QC can decrypt all private keys
priv_key_bytes = priv.to_bytes()
tweaked_privkey_bytes = tweak_taproot_privkey(priv_key_bytes, tweak_int)
tweaked_privkey = PrivateKey.from_bytes(tweaked_privkey_bytes)

print("Tweaked private key (WIF):", tweaked_privkey.to_wif())

# Derive tweaked public key and verify Taproot address
tweaked_pubkey_from_priv = tweaked_privkey.get_public_key()
print("Taproot address from tweaked private key:", tweaked_pubkey_from_priv.get_taproot_address().to_string())

assert taproot_address.to_string() == tweaked_pubkey_from_priv.get_taproot_address().to_string(), "Mismatch in Taproot addresses from public and private key tweaks!"
print("Both Taproot addresses match!")
