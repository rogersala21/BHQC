extern crate rand; 
use rand::rngs::OsRng;
use rand::RngCore;

extern crate curve25519_dalek_ng;
use curve25519_dalek_ng::scalar::Scalar;
extern crate merlin;
use merlin::Transcript;
extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

fn main() {
    let range_bit_num = 64; 
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(range_bit_num, 1);

let value_192: [u64; 3] = [
        0x1234567890abcdef,  // lower 64 bits
        0xfedcba9876543210,  // middle 64 bits
        0x1111222233334444,  // upper 64 bits
    ];    // let blinding = Scalar::random(&mut OsRng);
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);

    let blinding = Scalar::from_bytes_mod_order(bytes);
    // Create a single value range proof
    let mut prover_transcript = Transcript::new(b"doctest example");

    let (proof, committed_value) =
        RangeProof::prove_multiple(&bp_gens, &pc_gens, &mut prover_transcript, value, &blinding, range_bit_num)
        .unwrap();

    println!("Proof generated!");


    let mut verifier_transcript = Transcript::new(b"doctest example");
    assert!(
        proof
            .verify_multiple(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, range_bit_num)
            .is_ok()
    );
    println!("Proof verified!");
}
