import re
import argparse

def main():
    # Receives a list of source files to fuzz.

    parser  = argparse.ArgumentParser(description="Fuzz a contract to find out expected gas costs.")
    parser.add_argument("-b", dest="bin", action="store_true", help="Given files are in binary format")
    parser.add_argument("files", nargs="+", help="List of compiled files")

    args = parser.parse_args()

    if args.bin:
        chain = FuzzingChain(args.files)

    log = {}

    for i in range(args.iterations):
        chain.fuzz(log=log)
        pass






if __name__ == '__main__':
    main()