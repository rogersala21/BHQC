from src.modules.dleq import DLEQ
from src.modules.dleqag import DLEQAG 
from math import log2, ceil
from src.modules.curves import Secp192r1, Secp256k1
import secrets 
def test_dleq():
    number_of_entities = 10
    number_of_chunks = 3
    private_keys, dleqag_proofs, dleq_proofs, range_proofs = [], [], [], []
    b_x = 64 
    b_f = 3
    b_c = 124
    over_flow_bits = ceil(log2(number_of_entities))
    for id in range(number_of_entities):
        private_key_range = Secp192r1.field.n >> over_flow_bits
        private_keys.append(secrets.randbelow(private_key_range))
        dleqag_inst = DLEQAG(b_x, b_f, b_c, number_of_chunks, private_key_range, Secp256k1, Secp192r1)
        dleqag_proof, _ , bulletproof_input = dleqag_inst.proof_gen(private_keys[id])
        dleq_secp256k1_inst = DLEQ(Secp256k1)
        dleq_proof_secp256k1 = dleq_secp256k1_inst.proof_gen(dleqag_proof["r_HS"], private_keys[id])
        dleq_secp192r1_inst = DLEQ(Secp192r1)
        dleq_proof_secp192r1 = dleq_secp192r1_inst.proof_gen(dleqag_proof["r_LS"], private_keys[id])
        dleq_proofs.append({
            "dleq_256": dleq_proof_secp256k1, 
            "dleq_192": dleq_proof_secp192r1
        })
        dleqag_proofs.append(dleqag_proof)
        
