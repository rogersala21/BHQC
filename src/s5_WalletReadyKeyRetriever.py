import c2_PublicKeyAggregator as pub_agg
import c4_HoneypotCommitment as honeypot_commitment
import sys

def check_data_correctness(introduced_taproot_address):
    secp192r1_pub = pub_agg.main()
    network, calculated_taproot_address = honeypot_commitment.main(False)
    if introduced_taproot_address == calculated_taproot_address:
        print("Data is correct. The introduced taproot address matches the calculated one, proceeding with the next steps...\n")
        return secp192r1_pub
    else:
        print("Data is incorrect. The introduced taproot address does not match the calculated one.")
        print(f"Introduced address: {introduced_taproot_address}")
        print(f"Calculated address: {calculated_taproot_address}")
        print("Please check your data and try again...")
        sys.exit(0)


def main():
    print("Starting to check data correctness...")
    response2 = input("Make sure you have the public keys of all participants in the folder /outputs/coordinator/key_agg_input. And the ECIES outputs in /outputs/coordinator/honeypot_commitment. Do you want to continue? (yes/no): ")
    if response2.lower() == "yes":
        introduced_taproot_address = input("Please introduce the honeypot taproot address: ")
        secp192r1_pub = check_data_correctness(introduced_taproot_address)
    elif response2.lower() == "no":
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid input. Please enter 'yes' or 'no'.")
        sys.exit(1)

    #TODO: check if the PRIVATE key is in the expected format (compressed, hex, etc.)
    private_key_secp192r1 = input(f"Please introduce the secp192r1 private key corresponding to public key {secp192r1_pub} in ???? format: ")

    #TODO: DECRYPTION OF ALL ECIES OUTPUTS, SAVE THEM IN A LIST

    #TODO: AGGREGATION OF ALL DECRYPTED KEYS, AND GENERATE THE TWEAKED PRIVATE KEY (HONEYPOT PRIVATE KEY)

    #TODO: CONVERT THE HONEYPOT PRIVATE KEY TO WIF AND THEN USE DESCPIPTOR.PY TO GENERATE THE DESCRIPTOR READY TO IMPORT INTO BITCOIN CORE AND ALSO SAVE IT IN A FILE (DESCRIPTOR + HONEYPOT PRIVATE KEY IN WIF FORMAT)




if __name__ == "__main__":
    main()