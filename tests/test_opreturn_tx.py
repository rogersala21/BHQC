from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey, P2trAddress
from bitcoinutils.script import Script


def main():
    # always remember to setup the network
    setup("testnet")

    # the key that corresponds to the Taproot address
    priv = PrivateKey("your_private_key_wif_here")
    pub = priv.get_public_key()

    fromAddress = pub.get_taproot_address()
    print("From address:", fromAddress.to_string())

    # UTXO of fromAddress
    txid = "the_txid_of_your_utxo_here"
    vout = 0

    # amount in the input UTXO
    first_amount = to_satoshis(0.0024)
    amounts = [first_amount]

    # scriptPubKey of the input UTXO
    first_script_pubkey = fromAddress.to_script_pub_key()
    utxos_script_pubkeys = [first_script_pubkey]

    # destination address (Taproot)
    toAddress = P2trAddress("your_destination_address_here")

    # create transaction input from tx id of UTXO
    txin = TxInput(txid, vout)


    # For plain text message
    plain_text = "https://asdfghjklutr.dsfgh.de/nhyekai"
    # Convert to bytes and add to script with proper encoding
    op_return_script = ["OP_RETURN", plain_text.encode('utf-8').hex()]
    op_return_script = Script(op_return_script)


    # Create OP_RETURN output (with zero amount)
    op_return_output = TxOutput(0, op_return_script)

    # Create payment output (reduced by fees)
    payment_output = TxOutput(to_satoshis(0.0023), toAddress.to_script_pub_key())

    # create transaction with both outputs
    tx = Transaction([txin], [op_return_output, payment_output], has_segwit=True)

    print("\nRaw unsigned transaction:\n" + tx.serialize())
    print("\nTxId:", tx.get_txid())
    print("\nTxwId:", tx.get_wtxid())

    # sign taproot input
    sig = priv.sign_taproot_input(tx, 0, utxos_script_pubkeys, amounts)

    # add witness data
    tx.witnesses.append(TxWitnessInput([sig]))

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + tx.serialize())

    print("\nTxId:", tx.get_txid())
    print("\nTxwId:", tx.get_wtxid())

    print("\nSize:", tx.get_size())
    print("\nvSize:", tx.get_vsize())


if __name__ == "__main__":
    main()