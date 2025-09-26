pragma circom 2.0.2;


include "secp256k1.circom"; 
include "utils.circom";
include "../../modules/circomlib/circuits/bitify.circom";
include "../../modules/circomlib/circuits/comparators.circom";
include "../../modules/circomlib/circuits/sha256/sha256.circom";



template RangeProof(n, k, chunks) {
    signal input private_key[k]; 
    signal input G[2][k]; 
    signal input random_point[chunks][2][k];
    signal input commitments[chunks][2][k];
    signal input private_key_range[k]; 
    signal input pub_key_point[2][k];
//    ------------------------------------------------------------------------------    
    var sum;
    component multiplier[chunks + 1];
    component isEqual[2 * k * chunks + 2];
    component addPoints[chunks];
    signal computed_commitment[chunks][2][k];
    signal computed_public_key[2][k];
//    ------------------------------------------------------------------------------    
    component less_than = LessThan(n); 
    less_than.in[0] <== private_key[2];
    less_than.in[1] <== private_key_range[2];
    ///////////////// To do: check that private_key[3] is all zero 
    assert(less_than.out);
//    ------------------------------------------------------------------------------
    multiplier[0] = Secp256k1ScalarMult(n,k);
    multiplier[0].scalar <== private_key;
    multiplier[0].point <== G;
    computed_public_key <== multiplier[0].out;

    for(var arr_index = 0; arr_index < k; arr_index++){
        isEqual[arr_index] = IsEqual();
        isEqual[arr_index].in[0] <== computed_public_key[0][arr_index];
        isEqual[arr_index].in[1] <== pub_key_point[0][arr_index];
        isEqual[arr_index + k] = IsEqual();
        isEqual[arr_index + k].in[0] <== computed_public_key[1][arr_index];
        isEqual[arr_index + k].in[1] <== pub_key_point[1][arr_index];
        sum = sum + isEqual[arr_index].out + isEqual[arr_index + k].out;
    }

    isEqual[2 * k] = IsEqual();
    isEqual[2 * k].in[0] <== sum;
    isEqual[2 * k].in[1] <== 2 * k;
    assert(isEqual[2 * k].out);
//    ------------------------------------------------------------------------------

}
component main {public [private_key, private_key_range, G]} = RangeProof(64, 4, 3);


