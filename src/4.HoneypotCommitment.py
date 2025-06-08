import os
from bitcoinutils.setup import setup
from bitcoinutils.keys import PublicKey, PrivateKey
from bitcoinutils.utils import tweak_taproot_pubkey, tweak_taproot_privkey, tagged_hash

AGGKEY_DIR = "../outputs/coordinator/key_agg_output/aggregation_output.txt"

def create_commitment_from_folder(folder_path):
    commitment = ''
    for filename in sorted(os.listdir(folder_path)):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'r') as f:
                commitment += ''.join(line.strip() for line in f)
    return commitment

def get_agg_key(file_path):
    if os.path.isfile(file_path):
        with open(file_path, 'r') as f:
            return f.readline().strip() or None
    return None

def main():
    # Initialize Bitcoin testnet
    setup("testnet")

    # Get commitments from both folders (aggregated pubkey, and all ecies outputs)
    commitment1 = create_commitment_from_folder('../outputs/coordinator/key_agg_output')
    commitment2 = create_commitment_from_folder('../outputs/coordinator/honeypot_commitment')

    # Concatenate both commitments
    combined_commitment = commitment1 + commitment2
    combined_commitment_bytes = combined_commitment.encode('utf-8')

    #Get the aggregated public key from the coordinator output
    agg_key_hex = get_agg_key(AGGKEY_DIR)


    # Load internal public key
    internal_pubkey = PublicKey(agg_key_hex)
    internal_pubkey_bytes = internal_pubkey.to_bytes()

    # Generate the tweak using tagged_hash
    # Correct argument order: (data, tag)
    # Tagged hash is used to create a unique tweak based on the internal public key and the commitment message
    tap_tweak = tagged_hash(internal_pubkey_bytes + combined_commitment_bytes, "TapTweak")  # We ensure that the tweak is derived from the internal public key and the commitment message (unique)
    # TapTweak is a tag added to the data before hashing, used for protocol-specific tweaks, without tagging, if you hash the same data in different contexts, the output hashes could collide or be misinterpreted.
    print("Taproot tweak (hex):", tap_tweak.hex())
    tweak_int = int.from_bytes(tap_tweak, 'big')

    # Tweak the internal public key
    tweaked_pubkey_bytes, is_odd = tweak_taproot_pubkey(internal_pubkey_bytes,tweak_int)  # Returns tweaked public key bytes and whether the y-coordinate is odd or even
    prefix = b'\x03' if is_odd else b'\x02'  # Add prefix for compressed format
    compressed_key = prefix + tweaked_pubkey_bytes
    tweaked_pubkey_hex = compressed_key.hex()

    # Create tweaked public key and taproot address
    tweaked_pubkey = PublicKey.from_hex(tweaked_pubkey_hex)
    taproot_address = tweaked_pubkey.get_taproot_address()
    print("Taproot address from tweaked public key:", taproot_address.to_string())

    # TODO: Save the taproot address to a file
    # TODO: OP_RETURN tx for honeypot commitment (do a dialog and give the coordinator the option to generate a tx with op_ret)



if __name__ == "__main__":
    main()
