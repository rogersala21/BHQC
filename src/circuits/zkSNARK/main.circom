pragma circom 2.0.2;


include "secp256k1.circom"; 
include "utils.circom";
include "bigint.circom";
include "../../modules/circomlib/circuits/bitify.circom";
include "../../modules/circomlib/circuits/comparators.circom";
include "../../modules/circomlib/circuits/sha256/sha256.circom";



template RangeProof(n, k) {
    signal input private_key_chunks[k]; 
    signal input random_values[3][k];
    signal input G[2][k]; 
    signal input H[2][k];
    signal input commitments[3][2][k];
    signal input private_key_range[k]; 
    signal input pub_key_point[2][k];
//    ------------------------------------------------------------------------------     //
    var sum;
    component multiplier[2 * 3 + 1];
    component isPubKeyEqual[2 * k + 1];
    component isCommitEqual[2 * k * 3 + 1];
    component addPoints[3];
    component bigIngMult[2];
    signal computed_random_points[3][2][k];
    signal computed_pubkey_chunks[3][2][k];
    signal computed_commitments[3][2][k];
    signal computed_public_key[2][k];
//    ------------------------------------------------------------------------------    //
/////////////// Checking the range for the inputted private key 
///////////////     note that chunks can't be bigger than 64bits 
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
        sum = sum + isPubKeyEqual[arr_index].out + isPubKeyEqual[arr_index + k].out;
    }

    isPubKeyEqual[2 * k] = IsEqual();
    isPubKeyEqual[2 * k].in[0] <== sum;
    isPubKeyEqual[2 * k].in[1] <== 2 * k ;
    assert(isPubKeyEqual[2 * k].out);
//    ------------------------------------------------------------------------------
///////////// Checking the commitments 
    sum = 0; 
    for (var chunk_index = 0; chunk_index < 3; chunk_index++){
        multiplier[1 + chunk_index] = Secp256k1ScalarMult(n,k);
        multiplier[1 + chunk_index].scalar <== [private_key_chunks[chunk_index] * (chunk_index**2 - 3 * chunk_index + 2)/2, private_key_chunks[chunk_index] * (- chunk_index**2 + 2 * chunk_index)/2, private_key_chunks[chunk_index] * (chunk_index**2 - chunk_index)/2, 0];
        multiplier[1 + chunk_index].point <== G;
        computed_pubkey_chunks[chunk_index] <== multiplier[1 + chunk_index].out;
        multiplier[4 + chunk_index] = Secp256k1ScalarMult(n,k);
        multiplier[4 + chunk_index].scalar <== random_values[chunk_index];
        multiplier[4 + chunk_index].point <== H;
        computed_random_points[chunk_index] <== multiplier[4 + chunk_index].out;
        addPoints[chunk_index] = Secp256k1AddUnequal(n, k);
        addPoints[chunk_index].a <== computed_random_points[chunk_index];
        addPoints[chunk_index].b <== computed_pubkey_chunks[chunk_index];
        computed_commitments[chunk_index] <== addPoints[chunk_index].out;
        
        for(var arr_index = 0; arr_index < k; arr_index++){
            isCommitEqual[arr_index + 2*k * chunk_index] = IsEqual();
            isCommitEqual[arr_index + 2*k * chunk_index].in[0] <==  computed_commitments[chunk_index][0][arr_index];
            isCommitEqual[arr_index + 2*k * chunk_index].in[1] <== commitments[chunk_index][0][arr_index];
            isCommitEqual[arr_index + 2*k * chunk_index + k] = IsEqual();
            isCommitEqual[arr_index + 2*k * chunk_index + k].in[0] <== computed_commitments[chunk_index][1][arr_index];
            isCommitEqual[arr_index + 2*k * chunk_index + k].in[1] <== commitments[chunk_index][1][arr_index];
            sum = sum + isCommitEqual[arr_index + 2*k * chunk_index].out + isCommitEqual[arr_index + k + 2*k * chunk_index].out;
        }
    }
    isCommitEqual[2 * k * 3] = IsEqual();
    isCommitEqual[2 * k * 3].in[0] <== sum;
    isCommitEqual[2 * k * 3].in[1] <== 2 * k * 3 ;
    assert(isCommitEqual[2 * k * 3].out);

}
component main = RangeProof(64, 4);


