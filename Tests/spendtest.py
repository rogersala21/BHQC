from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import P2pkhAddress, PrivateKey, P2trAddress


def main():
    # always remember to setup the network
    setup("testnet")

    # the key that corresponds to the P2WPKH address
    priv = PrivateKey("your_private_key_here")

    pub = priv.get_public_key()

    fromAddress = pub.get_taproot_address()
    print(fromAddress.to_string())

    # UTXO of fromAddress
    txid = "your_txid_here"
    vout = 0

    # all amounts are needed to sign a taproot input
    # (depending on sighash)
    first_amount = to_satoshis(0.0025)
    amounts = [first_amount]

    # all scriptPubKeys are needed to sign a taproot input
    # (depending on sighash) but always of the spend input
    first_script_pubkey = fromAddress.to_script_pub_key()

    # alternatively:
    # first_script_pubkey = Script(['OP_1', pub.to_taproot_hex()])

    utxos_script_pubkeys = [first_script_pubkey]

    toAddress = P2trAddress("your_destination_address_here")

    change_txOut = P2trAddress("your_change_address_here")

    # create transaction input from tx id of UTXO
    txin = TxInput(txid, vout)

    # create transaction output
    txOut = TxOutput(to_satoshis(0.00001), toAddress.to_script_pub_key())
    change_txOut = TxOutput(to_satoshis(0.002), change_txOut.to_script_pub_key())

    # create transaction without change output - if at least a single input is
    # segwit we need to set has_segwit=True
    tx = Transaction([txin], [txOut, change_txOut], has_segwit=True)

    print("\nRaw transaction:\n" + tx.serialize())

    print("\ntxid: " + tx.get_txid())
    print("\ntxwid: " + tx.get_wtxid())

    # sign taproot input
    # to create the digest message to sign in taproot we need to
    # pass all the utxos' scriptPubKeys and their amounts
    sig = priv.sign_taproot_input(tx, 0, utxos_script_pubkeys, amounts)
    # print(sig)

    tx.witnesses.append(TxWitnessInput([sig]))

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + tx.serialize())

    print("\nTxId:", tx.get_txid())
    print("\nTxwId:", tx.get_wtxid())

    print("\nSize:", tx.get_size())
    print("\nvSize:", tx.get_vsize())


if __name__ == "__main__":
    main()
