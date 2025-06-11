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
    while True:
        data_correctness_response = input(
            "Make sure you have the public keys of all participants in the folder ../outputs/coordinator/key_agg_input. "
            "And the ECIES outputs in ../outputs/coordinator/honeypot_commitment. Do you want to continue? (yes/no): "
        )
        if data_correctness_response.lower() == "yes":
            introduced_taproot_address = input("Please introduce the honeypot taproot address: ")
            secp192r1_pub = check_data_correctness(introduced_taproot_address)
            break
        elif data_correctness_response.lower() == "no":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

    print("Strarting to decrypt ECIES outputs...")
    while True:
        secp192r1_private_response = input(f"Make sure you have the secp192r1 private key corresponding to public key {secp192r1_pub} in PEM format (PKCS8, unencrypted) into ../outputs/stealer/*.txt Do you want to continue? (yes/no): ")
        if secp192r1_private_response.lower() == "yes":

            break
        elif secp192r1_private_response.lower() == "no":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")


    #TODO: DECRYPTION OF ALL ECIES OUTPUTS, SAVE THEM IN A LIST

    #TODO: AGGREGATION OF ALL DECRYPTED KEYS, AND GENERATE THE TWEAKED PRIVATE KEY (HONEYPOT PRIVATE KEY)

    #TODO: CONVERT THE HONEYPOT PRIVATE KEY TO WIF AND THEN USE DESCPIPTOR.PY TO GENERATE THE DESCRIPTOR READY TO IMPORT INTO BITCOIN CORE AND ALSO SAVE IT IN A FILE (DESCRIPTOR + HONEYPOT PRIVATE KEY IN WIF FORMAT)







if __name__ == "__main__":
    main()