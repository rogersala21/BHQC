from src.modules.seedgen import seedgen
from src.modules.bitcoinkeygen import bitcoinkeygen




def main():
    print("Welcome to BHQC protocol!\n")
    print("Generating your Key Pair and saving into .txt files...\n")

    #Generation of seed
    seed = seedgen()
    print(f"Your seed: {seed}")

    #Generation of Bitcoin private key (dg)
    bitcoinkeygen(seed)





if __name__ == "__main__":
    main()