
const chai = require("chai");
const path = require("path");
const { Point } = require('@noble/secp256k1');
const {bigintToTuple, bufferToBigInt, read_json} = require("../src/modules/utils");
const circuitPath =  "../src/circuits/zkSNARK";
const inputPath = "test_inputs";
const wasm_tester = require("circom_tester").wasm;

describe("Test", function () {
    this.timeout(100000);
    it("Check the circuit", async () => {
        const cir = await wasm_tester(path.join(__dirname, circuitPath, "main.circom"));
        filePath= path.join(__dirname, inputPath + "/" + "input_SNARK_88308370623668056984220166548001497620511570460403953869190865758622127107717.json");
        proof_input = await read_json(filePath);
        const private_key_input = bigintToTuple(BigInt(proof_input.private_key));
        public_key_point = Point.BASE.multiply(BigInt(proof_input.private_key));
        const G_x = bigintToTuple(bufferToBigInt(Point.BASE.toBytes(false).slice(1,33))); 
        const G_y = bigintToTuple(bufferToBigInt(Point.BASE.toBytes(false).slice(33,65)));
        const H_x = bigintToTuple(BigInt(proof_input.H[0]));
        const H_y = bigintToTuple(BigInt(proof_input.H[1])); 
        const commitments = [
            [bigintToTuple(BigInt(proof_input.commitments[0][0])), bigintToTuple(BigInt(proof_input.commitments[0][1]))],
            [bigintToTuple(BigInt(proof_input.commitments[1][0])), bigintToTuple(BigInt(proof_input.commitments[1][1]))],
            [bigintToTuple(BigInt(proof_input.commitments[2][0])), bigintToTuple(BigInt(proof_input.commitments[2][1]))]
        ]
        const random_values = [
            bigintToTuple(BigInt(proof_input.random_values[0])),
            bigintToTuple(BigInt(proof_input.random_values[1])),
            bigintToTuple(BigInt(proof_input.random_values[2]))
        ]
        const private_key_range_input = bigintToTuple(BigInt(proof_input.private_key_range));
        const pk_x = bigintToTuple(bufferToBigInt(public_key_point.toBytes(false).slice(1,33))); 
        const pk_y =  bigintToTuple(bufferToBigInt(public_key_point.toBytes(false).slice(33,65)));        

        const circuit_inputs = {
            "private_key_chunks": private_key_input, 
            "G": [G_x, G_y], 
            "private_key_range": private_key_range_input, 
            "pub_key_point": [pk_x, pk_y]
        }
        await cir.calculateWitness(circuit_inputs, true); 
    }).timeout(1000000);
});
