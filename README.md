# BHQC
Bitcoin Honeypot for Quantum Computers

Bitcoinutils library is used.


## Flux of the code
Reminder: keep testing all small parts into testnet.

### Generator Script 1
This script will be executed individually by all the participants of the protocol.

- A pair of public (Pg) and private (dg) BTC keys are created randomly. (Taproot format for the public key).

### Merge script
The actual script protocol that needs some cooperation between the participants, to get all of them public keys.

- Obtain the aggregated Public key (Pgm) by aggregating all participants Public keys (Pg).
- Once the Pgm is obtained, the actual taproot address for the honeypot is calculated.
- Hash and truncate Pgm to obtain the smaller elliptic curve secp192r1 public key (Pp).

Send Pp to all participants.

### Generator Script 2
This is the "last" step of the protocol.

- All the participants need to encrypt their dg with Pp using ECIES and obtain C.
- Participants need to send C.

### Final Script????
- Funds sent to Pgm.
- All the information of the honeypot (Pp,C1,C2,C3....Cx) is added to script path of the taproot pubkey as a commitment.
- Add a IPFS link in the OP_RETURN with all the honeypot information and explanation plus encourage sending dust there.


### QC Redeem script
The target for a QC will be breaking a smaller elliptic curve private key dp, this will enable to decrypt al C's and in consequence, obtaining al dg's that after being aggregated, will enable spending all the funds of the honeypot.
This script recieves a dp and a BTC address (NO, BECAUSE IF MORE FUNDS ADDED LATER, SCRIPT JUST SPENDS THE FIRST INPUT) and returns a transaction ready to broadcast with all the honeypot funds sent to the desired address (NO, IT WILL RETURN THE PRIVATEKEY READY TO IMPORT INTO A WALLET).

## Important considerations
There are two main failure points with different consequences:

1· If all participants share dg they can move the funds of the honeypot, meaning that if just one person is honest, the protocol works.

2· If one participant encrypts anything that is not dg, the protocol fails because one dg is missing and the funds cannot be redeemed. This can be solved using ZeroKnowledge Proofs.