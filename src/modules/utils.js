const crypto = require("crypto");
const F1Field = require("ffjavascript").F1Field;
const Scalar = require("ffjavascript").Scalar;
const fs = require("fs");
exports.p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");




function bufferToBigInt(buf) {
  let result = 0n;
  for (const byte of buf) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

function buffer2bitArray(b) {
    const res = [];
    for (let i=0; i<b.length; i++) {
        for (let j=0; j<8; j++) {
            res.push((b[i] >> (7-j) &1));
        }
    }
    return res;
}

async function read_json(filePath) {
    try {
        const data = await fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('Error reading or parsing file:', err);
        return null;
    }
}
function bigintToTuple(x) {
  const mod = 2n ** 64n;
  const ret = [0n, 0n, 0n, 0n];

  let xTemp = x;
  for (let i = 0; i < ret.length; i++) {
    ret[i] = xTemp % mod;
    xTemp = xTemp / mod;
  }

  return ret;
}

function bitArray2buffer(a) {
    const len = Math.floor((a.length -1 )/8)+1;
    const b = new Buffer.alloc(len);

    for (let i=0; i<a.length; i++) {
        const p = Math.floor(i/8);
        b[p] = b[p] | (Number(a[i]) << ( 7 - (i%8)  ));
    }
    return b;
}



module.exports = {bigintToTuple, bitArray2buffer, buffer2bitArray, bufferToBigInt, read_json}