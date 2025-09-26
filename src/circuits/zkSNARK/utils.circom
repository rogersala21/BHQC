pragma circom 2.0.1; 

template concat3Inputwith256Bits(k, n){
    signal input firstInput [k][n];
    signal input secondInput [k][n];
    signal input thirdInput [k][n];
    var concatinated [k * n * 3]; 
    signal output out[k * 3 * n];
    for (var arr_index = 0; arr_index< k; arr_index++){
        for (var bit_index = 0; bit_index< n; bit_index++) {
            concatinated[bit_index + arr_index * n] = firstInput[arr_index][n - 1 - bit_index];
            concatinated[bit_index + arr_index * n + k* n] = secondInput[arr_index][n - 1 - bit_index];
            concatinated[bit_index + arr_index * n + k* n* 2] = thirdInput[arr_index][n - 1 - bit_index];
        }
    }
    out <-- concatinated;
}

template bits2scalar(n, k) { 
    signal input in[k*n]; 
    var reversedValue [k][n];
    var converted[k]; 
    signal output out [k];
    component bit2numConversion[k];
    for (var arr_index = 0; arr_index< k; arr_index++){
        for (var bit_index = 0; bit_index< n; bit_index++) {
            reversedValue[arr_index][n - 1 - bit_index] = in[bit_index + arr_index * n] ;
        }
        bit2numConversion[arr_index] = Bits2Num(n);
        bit2numConversion[arr_index].in <-- reversedValue[arr_index];
        converted[k - 1 - arr_index] = bit2numConversion[arr_index].out;
    }
    out <-- converted;
}