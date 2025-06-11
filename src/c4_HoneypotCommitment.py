import os
from bitcoinutils.setup import setup
from bitcoinutils.keys import PublicKey
from bitcoinutils.utils import tweak_taproot_pubkey, tagged_hash
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey
from bitcoinutils.script import Script

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

def create_op_return_tx(network, taproot_address):
    # always remember to setup the network
    setup(network)
    while True:
        response = input("Enter the private key WIF: ")
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

    plain_text = input("Enter the OP_RETURN message (plain text): ").strip()
    op_return_script = ["OP_RETURN", plain_text.encode('utf-8').hex()]
    op_return_script = Script(op_return_script)
    op_return_output = TxOutput(0, op_return_script)

    pay_amount_btc = float(input("Enter the payment output amount (in BTC): ").strip())
    payment_output = TxOutput(to_satoshis(pay_amount_btc), to_address.to_script_pub_key())

    tx = Transaction([txin], [op_return_output, payment_output], has_segwit=True)

    sig = priv.sign_taproot_input(tx, 0, utxos_script_pubkeys, amounts)
    tx.witnesses.append(TxWitnessInput([sig]))

    if network == "testnet":
        explorer_url = "https://mempool.space/testnet4/tx/preview#hex="
    else:
        explorer_url = "https://mempool.space/tx/preview#hex="

    print(f"\nRaw signed transaction ready to preview and broadcast here: {explorer_url}" + tx.serialize())


def main(ask_create_op_return=True):
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

    #Save the taproot address to a file
    with open('../outputs/coordinator/honeypot_address.txt', 'w') as f:
        f.write(taproot_address.to_string())
    print("Taproot address saved to ../outputs/coordinator/honeypot_address.txt" '\n')


    #OP_RETURN tx for funding honeypot give the coordinator the option to generate a tx with op_ret
    if ask_create_op_return:
        while True:
            response = input("Do you want to generate a funding transaction to the honeypot with OP_RETURN data? (yes/no): ")
            if response.lower() == "yes":
                create_op_return_tx(network, taproot_address)
                break
            elif response.lower() == "no":
                print("Exiting...")
                break
            else:
                print("Invalid input. Please enter 'yes' or 'no'.")

    return network, taproot_address.to_string(), tweak_int

if __name__ == "__main__":
    main()
