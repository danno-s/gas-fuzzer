import re
import argparse

import os
from os.path import abspath
import subprocess
import sys

from json import dumps, loads

from fuzzing_chain import FuzzingChain
from eth import constants
from eth.vm import forks

from solc import install_solc

from pprint import pprint

import logging

def main():
    # Receives a list of source files to fuzz.

    parser = argparse.ArgumentParser(description="Fuzz a contract to find out expected gas costs.")
    parser.add_argument("-n", "--iterations", metavar="N", type=int, default=100, help="number of blocks to mine in total")
    parser.add_argument("-tx", "--block-tx", metavar="T", type=int, default=20, help="number of transactions per block")
    parser.add_argument("-ff", "--frontier", action='store_const', dest="fork", const=forks.FrontierVM, help="use Frontier VM")
    parser.add_argument("-hf", "--homestead", action='store_const', dest="fork", const=forks.HomesteadVM, help="use Homestead VM")
    parser.add_argument("-twf", "--tangerine-whistle", action='store_const', dest="fork", const=forks.TangerineWhistleVM, help="use Tangerine Whistle VM")
    parser.add_argument("-sdf", "--spurious-dragon", action='store_const', dest="fork", const=forks.SpuriousDragonVM, help="use Spurious Dragon VM")
    parser.add_argument("-bf", "--byzantium", action='store_const', dest="fork", const=forks.ByzantiumVM, help="use Byzantium VM (default)")
    parser.add_argument("-cf", "--constantinople", action='store_const', dest="fork", const=forks.ConstantinopleVM, help="use Constantinople VM")
    parser.add_argument("files", nargs="+", help="List of compiled files")
    parser.add_argument("-r", "--rules", help="file with fuzzing rules")

    args = parser.parse_args()

    chain_class = FuzzingChain.configure(
        __name__ = 'Fuzzing Chain',
        vm_configuration = (
            (constants.GENESIS_BLOCK_NUMBER, args.fork if args.fork else forks.ByzantiumVM),
        )
    )

    contracts = compile(args.files, args.fork)

    logging.basicConfig(filename="fuzzing_log", level=logging.INFO)

    chain = chain_class.init(contracts, tx=args.block_tx, rules=args.rules)

    for _ in range(args.iterations):
        chain.fuzz()

def getEvmVersion(fork):
    if fork == forks.FrontierVM or fork == forks.HomesteadVM:
        # warning, version incompatible with compiler
        return "homestead"
    if fork == forks.TangerineWhistleVM:
        return "tangerineWhistle"
    if fork == forks.SpuriousDragonVM:
        return "spuriousDragon"
    if fork == forks.ConstantinopleVM:
        return "constantinople"
    return "byzantium"

def compile(files, fork):
    solc_path = os.path.join(os.environ["HOME"], ".py-solc/solc-v0.4.25/bin/solc")

    if not os.path.isfile(solc_path):
        install_solc('v0.4.25')

    sources = {}
    allow_paths = []
    for path in files:
        name = path.split('/')[-1]

        allowed_path = "/".join(abspath(path).split("/")[:-1])
        if allowed_path not in allow_paths:
            allow_paths.append("/".join(abspath(path).split("/")[:-1]))

        sources[name] = {
            'urls': [path]
        }

    evmVersion = getEvmVersion(fork)

    result = subprocess.run([
            solc_path,
            "--standard-json",
            "--allow-paths",
            ",".join(allow_paths)
        ],
        input = dumps({
            'language': 'Solidity',
            'sources': sources,
            'settings': {
                'evmVersion': evmVersion,
                'outputSelection': {
                    "*": {
                        "*": [
                            "abi",
                            "evm.bytecode.object",
                            "evm.methodIdentifiers",
                            "evm.gasEstimates"
                        ]
                    }
                }
            }
        }),
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
        check = True,
        encoding = "utf-8"
    )

    output = loads(result.stdout)

    if 'errors' in output:
        if any(error['type'] != "Warning" for error in output['errors']):
            pprint(output['errors'])
            sys.exit(1)
        # else: code compiled with errors

    return output['contracts']

if __name__ == '__main__':
    main()