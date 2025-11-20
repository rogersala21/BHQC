import json
import os
from math import log2, ceil
from p1_KeyPair_and_ProofGenerator import get_latest_participant_dir
from modules.tools import load_setup
from c2_PublicKeyAggregator import load_public_keys
SETUP_DIR = "../setup.json"
IPFS_DIR =  "../outputs/IPFS.json"
def load_rangeproof(proof_dir, number_of_chunks, b_x, over_flow_bits):
    proofs = []
    for index in range(number_of_chunks):
        proof_path = os.path.join(proof_dir, f"range_proof_{index}.json")
        if not os.path.exists(proof_path):
            print(f"Rangeproof file not found: {proof_path}")
            return None
        with open(proof_path, "r") as proof_file:
            rangeproof = json.load(proof_file)
        proofs.append({
            "range_in_bits":  b_x - int(index == number_of_chunks -1) * over_flow_bits, 
            "proof": rangeproof
        })
    return proofs


def main():
    max_number_of_entities, b_x, _, _ , number_of_chunks  = load_setup(SETUP_DIR)
    dir , number_of_participants = get_latest_participant_dir()
    dleqag_proofs, rangeproofs = [], []
    assert number_of_participants < max_number_of_entities, "Number of participants exeeding the allowed range!"
    #  For now we assume we are checking the last participant's proof 
    for participant_id in range(1, number_of_participants + 1):
        proof_dir = dir[:-1]
        participant_dir = proof_dir + str(participant_id)
        over_flow_bits = ceil(log2(max_number_of_entities))
        _, _, proof_data = load_public_keys(participant_dir + "/proofs/")
        dleqag_proofs.append(proof_data)
        rangeproof = load_rangeproof(participant_dir + "/proofs/", number_of_chunks, b_x, over_flow_bits)
        rangeproofs.append(rangeproof)
    
    proof = {
        "dleqag_proofs": dleqag_proofs, 
        "range_proofs": rangeproofs
    }
    with open( IPFS_DIR, "w") as proof_file:
        proof_file.write(json.dumps(proof))

if __name__ == "__main__":
    main()