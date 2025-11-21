import os
import hashlib
import json
from bitcoinutils.setup import setup
from bitcoinutils.keys import PublicKey
from bitcoinutils.utils import tweak_taproot_pubkey, tagged_hash
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey
from bitcoinutils.script import Script

def coords_to_compressed(pub_coords):
    #transform point coordinates to compressed pubkey
    x, y = pub_coords
    x_bytes = x.to_bytes(32, "big")          
    y_odd = y & 1
    prefix = b'\x03' if y_odd else b'\x02'
    comp = prefix + x_bytes
    return comp.hex(), comp

def load_internal_pubkey_hex_from_ipfs():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    ipfs_path = os.path.join(base_dir, 'outputs', 'IPFS.json')
    with open(ipfs_path, 'r') as f:
        j = json.load(f)
    # adjust path if your JSON structure differs
    pub_coords = j['dleqag_proofs'][0]['pub_key_256']
    hex_str, _ = coords_to_compressed(pub_coords)
    return hex_str


def compute_sha256_of_ipfs_file():
    #do the sha256 of IPFS.json
    
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    ipfs_path = os.path.join(base_dir, 'outputs', 'IPFS.json')
    with open(ipfs_path, 'rb') as f:
        data = f.read()
    hash = hashlib.sha256(data).digest()
    return hash, hash.hex()


def tweak_public_key(tweak, agg_key_hex):
     # Load internal public key
    internal_pubkey = PublicKey(agg_key_hex)
    internal_pubkey_bytes = internal_pubkey.to_bytes()
    
    #Ensure x-only (32 bytes)
    if len(internal_pubkey_bytes) == 33:
        xonly = internal_pubkey_bytes[1:]
    else:
        xonly = internal_pubkey_bytes

    # Generate the tweak using tagged_hash
    tap_tweak = tagged_hash(xonly + tweak, "TapTweak")  # We ensure that the tweak is derived from the internal public key and the commitment message (unique)
    tweak_int = int.from_bytes(tap_tweak, 'big')

    # Tweak the internal public key
    tweaked_pubkey_bytes, is_odd = tweak_taproot_pubkey(internal_pubkey_bytes,tweak_int)  # Returns tweaked public key bytes and whether the y-coordinate is odd or even
    prefix = b'\x03' if is_odd else b'\x02'  # Add prefix for compressed format
    compressed_key = prefix + tweaked_pubkey_bytes
    tweaked_pubkey_hex = compressed_key.hex()

    # Create tweaked public key and taproot address
    tweaked_pubkey = PublicKey.from_hex(tweaked_pubkey_hex)
    taproot_address = tweaked_pubkey.get_taproot_address()
    print("Honeypot Address:", taproot_address.to_string())

    return taproot_address

def create_op_return_tx(network, taproot_address):
    # always remember to setup the network
    setup(network)
    while True:
        response = input("Creating the honeypot funding transaction, please enter your private key WIF: ")
        try:
            priv = PrivateKey(response)
            print("Private key:", priv.to_wif())
            pub = priv.get_public_key()
            break  # Exit loop if successful
        except ValueError as e:
            print(f"Invalid WIF: {e}. Please try again.")


    from_address = pub.get_taproot_address()
    print("From address:", from_address.to_string())

    txid = input("Enter the txid of your UTXO: ").strip()
    vout = int(input("Enter the vout of your UTXO (as integer): ").strip())
    amount_btc = float(input("Enter the amount of the input UTXO (in BTC): ").strip())
    amounts = [to_satoshis(amount_btc)]

    utxos_script_pubkeys = [from_address.to_script_pub_key()]

    to_address = taproot_address

    txin = TxInput(txid, vout)

    plain_text = input("Enter the OP_RETURN message (IPFS CID): ").strip()
    op_return_script = ["OP_RETURN", plain_text.encode('utf-8').hex()]
    op_return_script = Script(op_return_script)
    op_return_output = TxOutput(0, op_return_script)

    pay_amount_btc = float(input("Enter the payment output amount (in BTC) (!!!REMINDER: the rest will be the fee!!!): ").strip())
    payment_output = TxOutput(to_satoshis(pay_amount_btc), to_address.to_script_pub_key())

    tx = Transaction([txin], [op_return_output, payment_output], has_segwit=True)

    sig = priv.sign_taproot_input(tx, 0, utxos_script_pubkeys, amounts)
    tx.witnesses.append(TxWitnessInput([sig]))

    if network == "testnet":
        explorer_url = "https://mempool.space/testnet4/tx/preview#tx="
    else:
        explorer_url = "https://mempool.space/tx/preview#tx="

    print(f"\nRaw signed transaction ready to preview and broadcast here: {explorer_url}" + tx.serialize())
    print(f"\nCheck your IPFS upload here: https://ipfs.io/ipfs/" + plain_text)


if __name__ == '__main__':
    # Initialize Bitcoin network
    while True:
        net_choice = input("Select network: (m)ainnet or (t)estnet?: ").strip().lower()
        if net_choice == "t":
            network = "testnet"
            break
        elif net_choice == "m":
            network = "mainnet"
            break
        else:
            print("Invalid input. Please enter 't' for testnet or 'm' for mainnet.")

    setup(network)
    agg_key_hex = load_internal_pubkey_hex_from_ipfs()
    digest_bytes, digest_hex = compute_sha256_of_ipfs_file()
    taproot_address = tweak_public_key(digest_bytes, agg_key_hex)
    create_op_return_tx(network, taproot_address)

