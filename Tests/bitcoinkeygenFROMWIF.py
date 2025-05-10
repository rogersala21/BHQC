from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey, PublicKey

def bitcoinkeygen():

    # always remember to setup the network
    setup("testnet")

    # create a private key (from our generated bits)
    priv = PrivateKey.from_wif("your_wif_here")

    # compressed is the default
    print("\nPrivate key WIF:", priv.to_wif(compressed=True))

    # get the public key
    pub = priv.get_public_key()

    taprootpub = pub.get_taproot_address()
    print("\nTaproot:", taprootpub.to_string())


    # compressed is the default
    print("Public key:", pub.to_hex(compressed=True))

    # get address from public key
    address = pub.get_address()

    # print the address and hash160 - default is compressed address
    print("Address:", address.to_string())
    print("Hash160:", address.to_hash160())

    print("\n--------------------------------------\n")

    # sign a message with the private key and verify it
    message = "The test!"
    signature = priv.sign_message(message)
    assert signature is not None
    print("The message to sign:", message)
    print("The signature is:", signature)

    if PublicKey.verify_message(address.to_string(), signature, message):
        print("The signature is valid!")
    else:
        print("The signature is NOT valid!")


if __name__ == "__main__":
    bitcoinkeygen()