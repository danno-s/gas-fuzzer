from eth import constants
from eth.chains.base import MiningChain
from eth.db.atomic import AtomicDB
from eth.consensus.pow import mine_pow_nonce
from eth.exceptions import VMError, Revert

from eth_typing import Address
from eth_utils import decode_hex, to_wei
from eth_keys import keys

from eth_abi import decode_abi, decode_single

from random import choice, randint

from fuzzer import SolidityFuzzer
from fuzzing_data import FuzzingData
from fuzzing_rules.constraint_parsing import new_constraint

from re import search

from pprint import pprint

from functools import reduce

import logging


class FuzzingChain(MiningChain):
    @classmethod
    def init(cls, contracts, ast, tx=10, progress=None, **kwargs):
        '''Builds a new MiningChain, with the given contract bytecodes, and an AtomicDB database.
        '''
        GENESIS_PARAMS = {
            'parent_hash': constants.GENESIS_PARENT_HASH,
            'uncles_hash': constants.EMPTY_UNCLE_HASH,
            'coinbase': constants.ZERO_ADDRESS,
            'transaction_root': constants.BLANK_ROOT_HASH,
            'receipt_root': constants.BLANK_ROOT_HASH,
            'difficulty': 1,
            'block_number': constants.GENESIS_BLOCK_NUMBER,
            'gas_limit': 100000000,
            'timestamp': 1514764800,
            'extra_data': constants.GENESIS_EXTRA_DATA,
            'nonce': constants.GENESIS_NONCE
        }

        sk = keys.PrivateKey(
            randint(1, 2 ** 32 - 1).to_bytes(32, byteorder='big'))
        pk = Address(sk.public_key.to_canonical_address())

        _faucet = {
            'sk': sk,
            'pk': pk
        }

        GENESIS_STATE = {
            _faucet['pk']: {
                # Practically infinite
                'balance': to_wei(2 ** 32 - 1, 'ether'),
                'nonce': 0,
                'code': b'',
                'storage': {}
            }
        }

        chain = cls.from_genesis(AtomicDB(), GENESIS_PARAMS, GENESIS_STATE)

        chain._faucet = _faucet
        logging.info(f"Faucet initialized at address: {pk}")

        chain.fuzzer = SolidityFuzzer(
            chain.transfer_from_faucet,
            faucet_sk=_faucet['sk'],
            **kwargs
        )

        chain.fuzzing_data = FuzzingData()
        chain.progress = progress

        # Number of transactions per block
        chain.txs = tx

        """
        Adresses of all the contracts being tested
        Dictionary defined as :
        {
            [address]: {
                [function]: {
                    'hash': [hash],
                    'args: [
                        arg1,
                        arg2,
                        ...
                    ],
                    'compilation_estimate': [estimate]
                }
            }
        }
        """
        chain.contracts = {}
        chain.contract_names = {}

        logging.info("CONTRACT TRANSACTIONS BEGIN\n")

        for filename, contracts in contracts.items():
            # Find the ast for this file
            ast_nodes = ast[filename]['ast']['nodes']
            for contract_name, desc in contracts.items():
                if all(abi['type'] != 'constructor' for abi in desc['abi']):
                    logging.info(
                        f"Skipped contract {contract_name} because it didn't have a constructor")
                    continue

                # Find the ast object for this contract
                contract_nodes = [
                    node for node in ast_nodes
                    if (
                        node['nodeType'] == 'ContractDefinition' and
                        node['name'] == contract_name
                    )
                ][0]['nodes']

                # Find the variable definitions in this contract
                variables = [
                    [node['name'], node['typeName']['name']]
                    for node in contract_nodes
                    if node['nodeType'] == 'VariableDeclaration'
                ]

                chain.fuzzer.register_contract(contract_name, variables)

                # Register all the functions in the fuzzer
                for node in contract_nodes:
                    if node['nodeType'] != 'FunctionDefinition':
                        continue
                    name = node['name'] if not node['isConstructor'] else '__constructor__'
                    parameters = [
                        [paramNode['name'], paramNode['typeName']['name']]
                        for paramNode in node['parameters']['parameters']
                    ]

                    def reduce_ast(acc, node):
                        if (type(node) is dict
                            and 'nodeType' in node
                            and node['nodeType'] == 'ExpressionStatement'
                            and node['expression']['nodeType'] == 'FunctionCall'
                        and node['expression']['expression']['name'] == 'require'):
                            constraint = new_constraint(
                                node['expression']['arguments'][0],
                                [name for name, type in parameters],
                                chain.call_function
                            )

                            if constraint:
                                acc.append(constraint)
                        elif type(node) is list:
                            acc += reduce(reduce_ast, node, [])
                        elif type(node) is dict:
                            acc += reduce(reduce_ast, node.values(), [])

                        return acc

                    # Extract the explicit constraints defined in the source code
                    constraints = reduce(reduce_ast, node['body']['statements'], [])
                    """ 
                    [
                        new_constraint(
                            expression['expression']['arguments'][0])
                        for expression in node['body']['statements']
                        if expression['nodeType'] == 'ExpressionStatement'
                        and expression['expression']['nodeType'] == 'FunctionCall'
                        and expression['expression']['expression']['name'] == 'require'
                    ] """

                    print(f'Constraints for {contract_name}.{name}: {constraints}')

                    chain.fuzzer.register_function(
                        contract_name, name, parameters, constraints)

                constructor = [abi for abi in desc['abi']
                               if abi['type'] == 'constructor'][0]
                call = chain.fuzzer.generate_args(contract_name, '__constructor__', [
                                                  arg for arg in constructor['inputs']], value=False)

                _, _, computation = chain.call_function(
                    constants.CREATE_CONTRACT_ADDRESS,
                    decode_hex(desc['evm']['bytecode']['object']),
                    call
                )

                chain.log_function_call(
                    contract_name, f"constructor", call['pk'], call['args'], call['value'], computation.get_gas_used())
                chain.fuzzing_data.set_expected_cost(
                    contract_name, f"constructor", desc['evm']['gasEstimates']['creation']['totalCost'])

                contract_address = computation.msg.storage_address

                chain.fuzzer.set_contract_address(contract_name, contract_address)

                chain.contract_names[contract_address] = contract_name
                chain.contracts[contract_address] = {}

                for abi in desc['abi']:
                    if abi['type'] != 'function':
                        continue
                    fname = abi['name']
                    fin = [inp for inp in abi['inputs']]
                    fout = [out for out in abi['outputs']]

                    chain.fuzzer.set_args(
                        contract_name,
                        fname,
                        [arg for arg in fin]
                    )

                    chain.fuzzer.set_out(
                        contract_name,
                        fname,
                        [arg['type'] for arg in fout]
                    )

                    chain.fuzzer.set_mutability(
                        contract_name,
                        fname,
                        abi['stateMutability'] == 'view' or abi['stateMutability'] == 'pure'
                    )

                    chain.contracts[contract_address][fname] = {
                        'in': fin,
                        'out': fout,
                        'payable': abi['payable']
                    }

                logging.info(" Compilation gas estimates:")

                for function, fhash_encoded in desc['evm']['methodIdentifiers'].items():
                    fname = function.split("(")[0]

                    fhash = decode_hex(fhash_encoded)
                    
                    chain.fuzzer.set_function_hash(contract_name, fname, fhash)
                    
                    chain.contracts[contract_address][fname]['hash'] = fhash
                    chain.contracts[contract_address][fname]['compilation_estimate'] = desc['evm']['gasEstimates']['external'][function]

                    function_signature = f"{function} => ({', '.join(arg['type'] for arg in chain.contracts[contract_address][fname]['out'])})"

                    logging.info(
                        f" {function_signature}: {desc['evm']['gasEstimates']['external'][function]}{' payable' if chain.contracts[contract_address][fname]['payable'] else ''}")
                    chain.fuzzing_data.set_expected_cost(
                        contract_name, fname, desc['evm']['gasEstimates']['external'][function])

        block = chain.get_vm().finalize_block(chain.get_block())

        nonce, mix_hash = mine_pow_nonce(
            block.number,
            block.header.mining_hash,
            block.header.difficulty
        )

        chain.mine_block(mix_hash=mix_hash, nonce=nonce)

        return chain

    def fuzz(self, log=None):
        '''Mines a block, executing a number of transactions to fuzz the contracts being tested.
        '''
        for _ in range(self.txs):
            contract_address = choice(list(self.contracts))
            contract_name = self.contract_names[contract_address]
            function_name = choice(list(self.contracts[contract_address]))

            function_hash = self.contracts[contract_address][function_name]['hash']
            call = self.fuzzer.generate_args(
                contract_name,
                function_name,
                [arg for arg in self.contracts[contract_address][function_name]['in']],
                value=self.contracts[contract_address][function_name]['payable']
            )

            _, _, computation = self.call_function(
                contract_address, function_hash, call)

            self.log_function_call(
                contract_name, function_name, call['pk'], call['args'], call['value'], computation.get_gas_used())
            out_types = [arg['type']
                         for arg in self.contracts[contract_address][function_name]['out']]
            try:
                computation.raise_if_error()
                logging.info(
                    f" Returned value: {decode_abi(out_types, computation.output)}")
            except Revert as r:
                logging.info(f" Call reverted. {r.args[0]}")
            except VMError as e:
                logging.info(f" Call resulted in error: {e}")
            except Exception as e:
                logging.info(
                    f" Something went wrong while decoding the output. {e}")

            if self.progress:
                with self.progress:
                    self.progress.update()

        block = self.get_vm().finalize_block(self.get_block())

        nonce, mix_hash = mine_pow_nonce(
            block.number,
            block.header.mining_hash,
            block.header.difficulty
        )

        self.mine_block(mix_hash=mix_hash, nonce=nonce)

    def call_function(self, to, function_hash, call):
        nonce = self.get_vm().state.account_db.get_nonce(call['pk'])

        tx = self.get_vm().create_unsigned_transaction(
            nonce=nonce,
            gas_price=0,
            gas=10000000,
            to=to,
            value=call['value'],
            data=b''.join([function_hash, call['data']])
        )

        signed_tx = tx.as_signed_transaction(call['sk'])

        header, receipt, computation = self.apply_transaction(signed_tx)

        return (header, receipt, computation)

    def transfer_from_faucet(self, pk, value):
        _, _, computation = self.call_function(
            pk,
            b'',
            {
                'pk': self._faucet['pk'],
                'sk': self._faucet['sk'],
                'data': b'',
                'value': value
            }
        )
        computation.raise_if_error()

    def log_function_call(self, cname, fname, pk, primitive_args, value, gas_used):
        logging.info(
            f''' 
            FUNCTION CALL: {cname}: {fname} ({", ".join(f"{_type} {name}: {value}" for name, _type, value in primitive_args)})
                CALLER: 0x{pk.hex()} 
                VALUE: {value} 
                GAS SPENT: {gas_used}''')

        self.fuzzing_data.register_call(cname, fname, gas_used)
