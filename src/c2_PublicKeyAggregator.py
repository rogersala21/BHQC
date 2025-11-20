import json
import os
import subprocess
from math import log2, ceil
from modules.dleqag import DLEQAG
from modules.dleq import DLEQ
from modules.curves import Secp192r1, Secp256k1
from p1_KeyPair_and_ProofGenerator import get_latest_participant_dir
from modules.tools import load_setup

SETUP_DIR = "../setup.json"


def load_public_keys(proof_dir):
    for filename in os.listdir(proof_dir):
        file_path = os.path.join(proof_dir, filename)
        if os.path.isfile(file_path) and filename.startswith("proof_") and filename.endswith(".json"):
            with open(file_path, "r") as f:
                data = json.load(f)
                btc_pubkey = data.get("pub_key_256")
                secp192_pubkey = data.get("pub_key_192")


    return Secp256k1.get_point(btc_pubkey[0], btc_pubkey[1]), Secp192r1.get_point(secp192_pubkey[0], secp192_pubkey[1]), data 

def proof_verification(proof, b_x, b_f, b_c, number_of_chunks, secret_range):

#   Verification of the proofs for discrete logarithm equality across groups
    dleqag_inst = DLEQAG(b_x, b_f, b_c, number_of_chunks, secret_range, Secp256k1, Secp192r1)
    dleqag_inst.proof_verification(proof)

#   Verification of the proofs for discrete logarithm equality of public key and commitments on SECP256K1
    dleq_inst_secp256k1 = DLEQ(Secp256k1)
    dleq_inst_secp256k1.proof_verification(proof["dleq_256"], Secp256k1.get_point(proof["X_256"][0], proof["X_256"][1]), Secp256k1.get_point(proof["pub_key_256"][0], proof["pub_key_256"][1]))
#   Verification of the proofs for discrete logarithm equality of public key and commitments on SECP192r1
    dleq_inst_secp192r1 = DLEQ(Secp192r1)
    dleq_inst_secp192r1.proof_verification(proof["dleq_192"], Secp192r1.get_point(proof["X_192"][0], proof["X_192"][1]), Secp192r1.get_point(proof["pub_key_192"][0], proof["pub_key_192"][1]))

def range_proof_verification(b_x, number_of_chunks, over_flow_bits, proof_dir, participant_id):
    proof_path = os.path.join("../../"+proof_dir, "proofs/range_proof_")
    for index in range(number_of_chunks):
        try:
            result = subprocess.run(
            ["node", "./modules/bulletproofs/bulletproof.js", "verify", f"{proof_path}{index}.json", str(int(b_x - int(index == number_of_chunks -1) * over_flow_bits))],  # pass arguments
            capture_output=True,
            text=True,
            check=True
            )
        except subprocess.CalledProcessError as e : 
            print(f"Verification failed with the error {e}")

    print("Range proofs verified")


def main():
    max_number_of_entities, b_x, b_f, b_c, number_of_chunks  = load_setup(SETUP_DIR)
    dir , number_of_participants = get_latest_participant_dir()
    aggregated_pub_key_192, aggregated_pub_key_256 = None, None
    assert number_of_participants < max_number_of_entities, "Number of participants exeeding the allowed range!"
    #  For now we assume we are checking the last participant's proof 
    for participant_id in range(1, number_of_participants + 1):
        proof_dir = dir[:-1]
        participant_dir = proof_dir + str(participant_id)
        over_flow_bits = ceil(log2(max_number_of_entities))

        pubkeybtc, pubkeyweak, proof_data = load_public_keys(participant_dir + "/proofs/")
        # Before aggregating any key, the proofs must be verified 
        proof_verification(proof_data, b_x, b_f, b_c, number_of_chunks, Secp192r1.field.n >> over_flow_bits)

        range_proof_verification(b_x, number_of_chunks, over_flow_bits, proof_dir, participant_id)
        # Will only aggregate values of the proofs are valid 
        if (aggregated_pub_key_192 == None and aggregated_pub_key_256 == None):
            aggregated_pub_key_256 = pubkeybtc
            aggregated_pub_key_192 = pubkeyweak
        else : 
            aggregated_pub_key_256 += pubkeybtc
            aggregated_pub_key_192 += pubkeyweak

if __name__ == "__main__":
    main()
