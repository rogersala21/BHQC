#!/bin/bash

set -ex  # Exit on any error

# wget https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_21.ptau

circom  --r1cs --wasm ../src/circuits/zkSNARK/main.circom -o ../outputs/zkSNARK 2>/dev/null

NODE_OPTIONS="--max-old-space-size=15288" snarkjs plonk setup ../outputs/zkSNARK/main.r1cs ppot_0080_24.ptau ../outputs/zkSNARK/main.zkey

snarkjs zkey export verificationkey ../outputs/zkSNARK/main.zkey src/prover/verification_key.json
