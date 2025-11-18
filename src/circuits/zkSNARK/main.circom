pragma circom 2.0.2;


include "secp256k1.circom"; 
include "utils.circom";
include "bigint.circom";
include "../../modules/circomlib/circuits/bitify.circom";
include "../../modules/circomlib/circuits/comparators.circom";
include "../../modules/circomlib/circuits/sha256/sha256.circom";



template RangeProof(n, k) {
    signal input private_key_chunks[k]; 
    signal input G[2][k]; 
    signal input private_key_range[k]; 
    signal input pub_key_point[2][k];
//    ------------------------------------------------------------------------------     //
    component multiplier[2 * 3 + 1];
    component isPubKeyEqual[2 * k ];
    component isCommitEqual[2 * k * 3];
    component addPoints[3];
    signal computed_pubkey_chunks[3][2][k];
    signal computed_public_key[2][k];
////    ------------------------------------------------------------------------------    //
///////////////// Checking the range for the inputted private key 
/////////////////     note that chunks can't be bigger than 64bits 
    component less_than = BigLessThan(n, k); 
    less_than.a <== private_key_chunks;
    less_than.b <== private_key_range;
    assert(less_than.out);
//    ------------------------------------------------------------------------------    //
/////////////// Checking the internal computed public key with the public key 
    multiplier[0] = Secp256k1ScalarMult(n,k);
    multiplier[0].scalar <== private_key_chunks;
    multiplier[0].point <== G;
    computed_public_key <== multiplier[0].out;

    for(var arr_index = 0; arr_index < k; arr_index++){
        isPubKeyEqual[arr_index] = IsEqual();
        isPubKeyEqual[arr_index].in[0] <== computed_public_key[0][arr_index];
        isPubKeyEqual[arr_index].in[1] <== pub_key_point[0][arr_index];
        isPubKeyEqual[arr_index + k] = IsEqual();
        isPubKeyEqual[arr_index + k].in[0] <== computed_public_key[1][arr_index];
        isPubKeyEqual[arr_index + k].in[1] <== pub_key_point[1][arr_index];
        assert(isPubKeyEqual[arr_index].out);
        assert(isPubKeyEqual[arr_index + k].out);
    }
}
component main {public[G, pub_key_point, private_key_range]} = RangeProof(64, 4);


