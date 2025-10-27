
const chai = require("chai");
const path = require("path");
const crypto = require("crypto");
const secp256k1 = require('secp256k1');
const fs = require("fs");
const { Point, CURVE } = require('@noble/secp256k1');
const {bigintToTuple, bufferToBigInt, buffer2bitArray} = require("../src/utils");
const { json } = require("stream/consumers");
const circuitPath =  "../src/circuits/zkSNARK";
const inputPath = "../outputs/participant/proofs";
const assert = chai.assert;
const wasm_tester = require("circom_tester").wasm;

async function read_json(filePath) {
    try {
        const data = await fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('Error reading or parsing file:', err);
        return null;
    }
}
describe("Test", function () {
    this.timeout(100000);
    it("Check the circuit", async () => {
        const cir = await wasm_tester(path.join(__dirname, circuitPath, "main.circom"));
        const CURVE_N = BigInt("115792089237316195423570985008687907852837564279074904382605163141518161494337");
        filePath= path.join(__dirname, inputPath + "/" + "input_SNARK_88308370623668056984220166548001497620511570460403953869190865758622127107717.json");
        // data = fs.readFile(filePath, 'utf8');
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
            "random_values": random_values, 
            "commitments": commitments, 
            "H": [H_x, H_y],
            "pub_key_point": [pk_x, pk_y]
        }
        console.log(circuit_inputs);

        const witness = await cir.calculateWitness(circuit_inputs, true); 
    }).timeout(1000000);
});
