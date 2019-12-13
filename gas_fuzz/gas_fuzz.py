import re
import argparse

import os
from os.path import abspath
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

from glob import glob

from json import dumps, loads

from fuzzing_chain import FuzzingChain
from fuzzing_data import FuzzingData
from progress import ProgressBar
from eth import constants
from eth.vm import forks

from solc import install_solc

from pprint import pprint

import logging
import colorlog


def main():
    # Receives a list of source files to fuzz.
    parser = argparse.ArgumentParser(
        description="Fuzz a contract to find out expected gas costs.")
    parser.add_argument("-tx", "--block-tx", metavar="T", type=int, default=10,
                        help="average number of transactions executed per function")
    parser.add_argument("-ff", "--frontier", action='store_const',
                        dest="fork", const=forks.FrontierVM, help="use Frontier VM")
    parser.add_argument("-hf", "--homestead", action='store_const',
                        dest="fork", const=forks.HomesteadVM, help="use Homestead VM")
    parser.add_argument("-twf", "--tangerine-whistle", action='store_const',
                        dest="fork", const=forks.TangerineWhistleVM, help="use Tangerine Whistle VM")
    parser.add_argument("-sdf", "--spurious-dragon", action='store_const',
                        dest="fork", const=forks.SpuriousDragonVM, help="use Spurious Dragon VM")
    parser.add_argument("-bf", "--byzantium", action='store_const', dest="fork",
                        const=forks.ByzantiumVM, help="use Byzantium VM (default)")
    parser.add_argument("-cf", "--constantinople", action='store_const',
                        dest="fork", const=forks.ConstantinopleVM, help="use Constantinople VM")
    parser.add_argument("-s", "--simulations", metavar="S", type=int,
                        default=1, help="number of total simulations to execute")
    parser.add_argument("file", help="File with all contracts to fuzz")
    parser.add_argument("-r", "--rules", help="file with fuzzing rules")
    parser.add_argument("-b", "--batch", action='store_true',
                        help="process all files in the directory pointed by file")
    parser.add_argument("-l", "--log", type=int, default=2,
                        help="Log level to be used. From 0 to 5, CHAIN DEBUG (0), DEBUG (1), INFO (2, default), WARNING (3), ERROR (4), CRITICAL (5)")

    args = parser.parse_args()

    files = [args.file]
    if args.batch:
        files = glob(f"{args.file}/*.sol")

    for file in files:
        compiled = compile(file, args.fork)

        total_functions = count_functions(compiled['contracts'])
        progress = ProgressBar(total_ops=args.simulations * total_functions *
                               args.block_tx, preamble=f"Fuzzing {getFileName(file)}.sol")

        def simulation_runner():
            chain_class = FuzzingChain.configure(
                __name__='Fuzzing Chain',
                vm_configuration=(
                    (constants.GENESIS_BLOCK_NUMBER,
                     args.fork if args.fork else forks.ByzantiumVM),
                )
            )
            colorlog.basicConfig(level=args.log * 10, format='%(log_color)s[%(levelname)-8s %(threadName)10s]%(reset)s %(message)s')
            logging.addLevelName(0, "CHAIN DEBUG")

            chain = chain_class.init(
                compiled['contracts'], ast=compiled['sources'], tx=args.block_tx, rules=args.rules, progress=progress)

            for _ in range(total_functions):
                chain.fuzz()

            return chain.fuzzing_data

        total_data = FuzzingData()

        with ThreadPoolExecutor(thread_name_prefix="Simulation") as executor:
            future_to_id = {executor.submit(
                simulation_runner): i for i in range(args.simulations)}

            for future in as_completed(future_to_id):
                sim_id = future_to_id[future]
                try:
                    total_data.merge(future.result())
                except Exception as exc:
                    logging.critical(
                        f'Simulation {sim_id} generated an exception:\n{type(exc).__name__}:\n\t{exc}')

        sys.stdout.write("\033[K")
        print("Saving results...", end="\r")
        total_data.export(folder="results", filename=f"{getFileName(file)}")


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


def compile(file, fork):
    solc_path = os.path.join(
        os.environ["HOME"], ".py-solc/solc-v0.4.25/bin/solc")

    if not os.path.isfile(solc_path):
        install_solc('v0.4.25')

    sources = {}
    allow_paths = []

    name = file.split('/')[-1]

    allowed_path = "/".join(abspath(file).split("/")[:-1])
    if allowed_path not in allow_paths:
        allow_paths.append("/".join(abspath(file).split("/")[:-1]))

    sources[name] = {
        'urls': [file]
    }

    evmVersion = getEvmVersion(fork)

    result = subprocess.run([
        solc_path,
        "--standard-json",
        "--allow-paths",
        ",".join(allow_paths)
    ],
        input=dumps({
            'language': 'Solidity',
            'sources': sources,
            'settings': {
                'evmVersion': evmVersion,
                'outputSelection': {
                    "*": {
                        "*": [
                            "abi",
                            "metadata",
                            "evm.bytecode.object",
                            "evm.methodIdentifiers",
                            "evm.gasEstimates"
                        ],
                        "": [
                            "ast"
                        ]
                    }
                }
            }
        }),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        encoding="utf-8"
    )

    output = loads(result.stdout)

    if 'errors' in output:
        if any(error['type'] != "Warning" for error in output['errors']):
            print(f"Errores al compilar {file}")
            raise RuntimeError(output['errors'])
        # else: code compiled with errors

    return output


def count_functions(contracts):
    counter = 0
    for filename, file_contracts in contracts.items():
        for contract, desc in file_contracts.items():
            for obj in desc['abi']:
                counter = counter + 1 if obj['type'] == 'function' else counter

    return counter


def getFileName(file):
    fileNamePattern = re.compile(r'(?P<fileName>.*?).sol')

    lastFileName = os.path.basename(os.path.normpath(file))

    match = re.search(fileNamePattern, lastFileName)

    if match:
        return match.group(1)
    raise ValueError("Invalid filename (couldn't parse)")


if __name__ == '__main__':
    main()
