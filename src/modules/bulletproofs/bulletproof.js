const bulletproofs = require('bulletproof-js');
const EC = require('elliptic').ec;
const { assert, expect } = require('chai');
const ProofFactory = bulletproofs.ProofFactory;
const ProofUtils = bulletproofs.ProofUtils;
const secp256k1 = bulletproofs.Constants.secp256k1;
const ec = new EC('secp256k1');
const fs = require("fs"); 
const path = require("path");

function proof_gen(secret, random, range_in_bit_size){
    const low = 0n; 
    const G = ec.g;
    const H = ProofUtils.getnewGenFromHashingGen(G);
    const V = ProofUtils.getPedersenCommitment(secret, random, secp256k1.n, H);

    const uncompr_proof = ProofFactory.computeBulletproof(secret, random, V, G, H, low, range_in_bit_size, secp256k1.n, false);
    return uncompr_proof.toJson(true);
}
function proof_verif(range_in_bits, proof_json){
    const uncompr_proof_inst = bulletproofs.UncompressedProofs; 
    const uncompr_proof = uncompr_proof_inst.fromJsonString(proof_json); 
    assert (uncompr_proof.verify(0n, range_in_bits), "proof is invalid");
    console.log("Proof is valid");
}

function main(){
    const args = process.argv.slice(2);
    const functionality = args[0] || "help"; 
    const proof_file_dir = args[1] || "./";
    const file_path = path.join(__dirname, proof_file_dir);

    if (functionality == "gen"){
        const range_in_bit = BigInt(args[2] || 0n); 
        const secret = BigInt(args[3] || 0n);         
        const random = BigInt(args[4] || 0n); 
        if (secret == 0n || range_in_bit == 0n || random == 0n){
            console.log("Check help to see how the proof generation command works");
            process.exit(1);
        }
        const proof_index = args[5] || 0;
        proof = proof_gen(secret, random, range_in_bit);
        fs.writeFileSync(`${file_path}proof${proof_index}.json`, proof);
    }
    else if (functionality == "verify"){
        if (range_in_bit == 0n){
            console.log("Check help to see how the proof verification command works");
            process.exit(1);
        }
        try {
            const proof = fs.readFileSync(file_path, 'utf8');
            proof_verif(range_in_bit, proof);
        }
        catch(err){
            console.log(err);
        }
    }
    else if (functionality == "help") { 
        console.log(" run the file with the following arguments");
        console.log(" gen 'directory_to_write_the_proof' 'range_in_number_of_bits' 'secret' 'random_value' 'index_of_proof_file' ");
        console.log(" verify 'path_of_proof_file' 'range_in_number_of_bits' ");
        console.log(" proof paths must be relative");
    }
}

main();
