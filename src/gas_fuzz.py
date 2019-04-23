import re
import argparse
from fuzzing_chain import FuzzingChain
from eth import constants
from eth.vm import forks

def main():
    # Receives a list of source files to fuzz.

    parser  = argparse.ArgumentParser(description="Fuzz a contract to find out expected gas costs.")
    parser.add_argument("-b", "--binary", dest="bin", action="store_true", help="if the given files are the compiled bytecode or not")
    parser.add_argument("-n", "--iterations", metavar="N", type=int, default=100, help="number of blocks to mine in total")
    parser.add_argument("-tx", "--block-tx", metavar="T", type=int, default=20, help="number of transactions per block")
    parser.add_argument("-ff", "--frontier", action='store_const', dest="fork", const=forks.FrontierVM, help="use Frontier VM")
    parser.add_argument("-hf", "--homestead", action='store_const', dest="fork", const=forks.HomesteadVM, help="use Homestead VM")
    parser.add_argument("-twf", "--tangerine-whistle", action='store_const', dest="fork", const=forks.TangerineWhistleVM, help="use Tangerine Whistle VM")
    parser.add_argument("-sdf", "--spurious-dragon", action='store_const', dest="fork", const=forks.SpuriousDragonVM, help="use Spurious Dragon VM")
    parser.add_argument("-bf", "--byzantium", action='store_const', dest="fork", const=forks.ByzantiumVM, help="use Byzantium VM (default)")
    parser.add_argument("-cf", "--constantinople", action='store_const', dest="fork", const=forks.ConstantinopleVM, help="use Constantinople VM")
    parser.add_argument("files", nargs="+", help="List of compiled files")

    args = parser.parse_args()

    print(args)

    chain_class = FuzzingChain.configure(
        __name__ = 'Fuzzing Chain',
        vm_configuration = (
            (constants.GENESIS_BLOCK_NUMBER, args.fork if args.fork else forks.ByzantiumVM),
        )
    )

    if args.bin:
        chain = chain_class.init(args.files, tx = args.block_tx)

    log = {}

    for _ in range(args.iterations):
        chain.fuzz(log=log)
        pass

if __name__ == '__main__':
    main()