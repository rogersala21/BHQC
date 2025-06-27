# BHQC: Bitcoin Honeypot for Quantum Computers

**Honeypot Address Generation Protocol (HAGP)**

This project implements a distributed protocol to create a Bitcoin honeypot address that is quantum-vulnerable by design. The honeypot serves as a public alert: if its funds are ever spent, it signals that a quantum computer has likely broken the ECDLP on `secp192r1` (and is approaching the security of Bitcoin's `secp256k1`). The protocol is implemented in Python and leverages several cryptographic libraries.

---

## Protocol Overview: HAGP

The Honeypot Address Generation Protocol (HAGP) is a multi-phase, distributed protocol involving `n` participants and a coordinator. It ensures:

1. **Compatibility**: The honeypot address is a standard Taproot address, fully compatible with Bitcoin, but with security reduced to that of `secp192r1`.
2. **Correctness**: Even with up to `k < n` malicious participants, a quantum computer able to break `secp192r1` can retrieve the funds.
3. **Robustness**: The honeypot private key is unknown as long as at least one participant is honest.
4. **Verifiability**: All data and steps are publicly verifiable.

### Key Naming Convention

- **(Pb, db)**: Public/private keys on `secp256k1` (Bitcoin standard).
- **(Pw, dw)**: Public/private keys on `secp192r1` (weakened for quantum feasibility).
- Suffixes `b` and `w` stand for Bitcoin and Weak, respectively.

---

## Protocol Phases

### 1. Key Pair Generation (p1_KeyPairGenerator.py)

- Each participant generates a random Bitcoin private key (**dbi**) and derives the corresponding public key (**Pbi**) using `secp256k1`.
- Outputs are saved in `../outputs/participant/keys`.

### 2. Public Key Aggregation (c2_PublicKeyAggregator.py)

- The coordinator aggregates all **Pbi** into a single public key (**Pb**) via elliptic curve point addition.
- **Pb** is hashed (SHA-256), truncated to 24 bytes, and used as the x-coordinate to derive a point (**Pw**) on `secp192r1`. If invalid, the process repeats.
- Results are saved in `../outputs/coordinator/key_agg_output/aggregation_output.txt`.

### 3. Key Encryption (p3_ReducedSecurityKeyCypher.py)

- Participants verify the received **Pb** and **Pw**.
- Each **dbi** is encrypted using ECIES (with AES-CBC) and **Pw**.
- Outputs (**Ei** = (Pbi, ci, IVi, Pei)) are saved in `../outputs/participant/ecies_output`.

### 4. Honeypot Commitment (c4_HoneypotCommitment.py)

- The coordinator collects all **Ei** and creates a commitment including **Pb**, **Pw**, the number of hashes, and all **Ei**.
- The commitment is hashed and used to tweak **Pb**, producing the final Taproot address (**HA**).
- The address is saved in `../outputs/coordinator/honeypot_address.txt`.
- A funding transaction is created with an OP_RETURN linking to a webpage with all protocol data.

### 5. Redemption (a5_WalletReadyKeyRetriever.py)

- In a post-quantum scenario, an attacker with **dw** can decrypt all **ci** to recover each **dbi**.
- All **dbi** are aggregated to reconstruct the final private key (**db**) for **Pb**.
- The tweaked private key is derived and transformed into a wallet descriptor ready to be imported into Bitcoin Core to spend the funds.

---

## Implementation Details

- **Languages/Libraries**: Python, `bitcoinutils`, `coincurve`, `cryptography`, `tinyec`, `secrets`, `hashlib`
- **Directory Structure**:
  - `outputs/participant/keys`: Participant key pairs
  - `outputs/participant/ecies_output`: Encrypted keys
  - `outputs/coordinator/key_agg_input`: Public keys for aggregation
  - `outputs/coordinator/key_agg_output`: Aggregation results
  - `outputs/coordinator/honeypot_commitment`: Commitment data
  - `outputs/coordinator/honeypot_address.txt`: Final address
  - `outputs/attacker/bitcoin_core_import.txt`: Wallet descriptor

---

## Limitations & Future Work

- **Zero-Knowledge Proofs**: Not yet implemented; would ensure each ciphertext is a valid encryption of a participant's private key.
- **Decentralization**: Current protocol uses a coordinator; future work should remove this trust assumption.
- **Data Hosting**: Currently uses centralized web hosting; decentralized storage (e.g., IPFS) is recommended for future versions.
- **Mainnet Deployment**: Protocol is a proof-of-concept; further improvements are needed for mainnet use.

---

## Testing

- Extensive tests for key aggregation, hash-to-curve, and edge cases (see `/tests/`).
- 100% success rate in all tested scenarios.
- Special tests for invalid points and aggregation edge cases.

---

## References

- [bitcoinutils](https://github.com/karask/python-bitcoin-utils)
- [coincurve](https://github.com/ofek/coincurve)
- [cryptography](https://cryptography.io/)
- [tinyec](https://github.com/alexmgr/tinyec)
