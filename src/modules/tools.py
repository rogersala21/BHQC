import sys
from cryptography.hazmat.primitives import serialization
from coincurve import PrivateKey
from bitcoinutils.keys import PrivateKey as BitcoinPrivateKey
from bitcoinutils.utils import tweak_taproot_privkey
from modules.descriptor import descsum_create
from modules.curves import Secp256k1
import os 
import json

def check_private_key(secp192r1_privatekey_raw, secp192r1_pub):
    secp192r1_processed = serialization.load_pem_private_key(
        secp192r1_privatekey_raw.encode(),
        password=None,
    )

    receiver_public_key = secp192r1_processed.public_key()
    public_key_bytes = receiver_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

    check = (public_key_bytes.hex() == secp192r1_pub)
    if check:
        print("The secp192r1 private key corresponds to the public key.\n")
        return secp192r1_processed
    else:
        print("The secp192r1 private key does not correspond to the public key.")
        print(f"Private key public key: {public_key_bytes.hex()}")
        print(f"Expected public key: {secp192r1_pub}")
        print("Please check your private key and try again...")
        sys.exit(0)



def wif_aggregation(list_decrypted_privates):

    # Convert WIF to coincurve.PrivateKey
    coincurve_privs = []
    for wif in list_decrypted_privates:
        btc_priv = BitcoinPrivateKey(wif)
        priv_bytes = btc_priv.to_bytes()
        cc_priv = PrivateKey(priv_bytes)
        coincurve_privs.append(cc_priv)


    # Aggregate the private keys
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    x_sum = sum(int.from_bytes(priv.secret, 'big') for priv in coincurve_privs) % n
    agg_secret = PrivateKey(x_sum.to_bytes(32, 'big'))

    # Convert the aggregated private key to Bitcoin WIF format
    agg_secret_bytes = agg_secret.secret  # 32 bytes
    btc_priv = BitcoinPrivateKey.from_bytes(agg_secret_bytes)
    wif = btc_priv.to_wif()

    return wif

def tweak_wif_key(wif_before_tweak, tweak_int):
    priv = BitcoinPrivateKey(wif_before_tweak)
    priv_key_bytes = priv.to_bytes()
    tweaked_privkey_bytes = tweak_taproot_privkey(priv_key_bytes, tweak_int)
    tweaked_privkey = BitcoinPrivateKey.from_bytes(tweaked_privkey_bytes)

    return tweaked_privkey.to_wif()




def create_wallet_descriptor(honeypot_wif):
    descriptor = f"tr({honeypot_wif})"
    descriptor_with_checksum = descsum_create(descriptor)
    print("Creating wallet descriptor ready to import into Bitcoin Core... \n")
    lines = [
        'createwallet "BHQC"',
        '',
        'importdescriptors \'[{',
        f'  "desc": "{descriptor_with_checksum}",',
        '  "timestamp": 0,',
        '  "label": "Honeypot"',
        '}]\''
    ]

    with open('../outputs/attacker/bitcoin_core_import.txt', 'w') as f:
        for line in lines:
            f.write(line + '\n')

    print("Wallet descriptor created and saved in ../outputs/attacker/bitcoin_core_import.txt")

    print("Content of the file:")
    with open('../outputs/attacker/bitcoin_core_import.txt', 'r') as f:
        content = f.read()
        print(content)

def bigint_to_tuple (value: str | int ):
    if type(value) == str: 
        value = int(value)
    mod = 2 ** 64 
    result = []
    assert value <= 2 ** 256, "value does not fit in 256 bits"
    temp_value = value 
    for index in range(4):
        result.append(temp_value % mod)
        temp_value = temp_value // mod 
    
    return result

def to_snark_input(proof):
    private_key_input = bigint_to_tuple(proof["private_key"])
    private_key_range = bigint_to_tuple(proof["private_key_range"])
    G = [bigint_to_tuple(Secp256k1.Gx), bigint_to_tuple(Secp256k1.Gy)]
    pub_key_point = [bigint_to_tuple(proof["pub_key_point"][0]), bigint_to_tuple(proof["pub_key_point"][1])]
    circuit_input = {
        "private_key_chunks": private_key_input, 
        "G": G, 
        "private_key_range": private_key_range, 
        "pub_key_point": pub_key_point
    }
    return circuit_input

def load_setup(setup_dir):
    # Load setup data from JSON file
    if not os.path.exists(setup_dir):
        print(f"Setup file not found: {setup_dir}")
        return None
    with open(setup_dir, "r") as setup_file:
        setup_data = json.load(setup_file)
    
    return setup_data.get("max_num_participants"), setup_data.get("number_of_bits_of_secret_chunks"), setup_data.get("failure_rate"), setup_data.get("number_of_bits_of_challenge"), setup_data.get("number_of_chunks")
