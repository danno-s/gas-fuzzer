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

from re import search

from pprint import pprint

import logging

class FuzzingChain(MiningChain):
    @classmethod
    def init(cls, standard_output, tx = 10, **kwargs):
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
            'gas_limit': 3141592,
            'timestamp': 1514764800,
            'extra_data': constants.GENESIS_EXTRA_DATA,
            'nonce': constants.GENESIS_NONCE
        }

        sk = keys.PrivateKey(randint(1, 2 ** 32 - 1).to_bytes(32, byteorder='big'))
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
            faucet_sk =_faucet['sk'], 
            **kwargs
        )

        chain.fuzzing_data = FuzzingData()

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

        logging.info("CONTRACT TRANSACTIONS BEGIN\n")

        for _, contracts in standard_output.items():
            for contract_name, desc in contracts.items():
                constructor = [abi for abi in desc['abi'] if abi['type'] == 'constructor'][0]
                call = chain.fuzzer.generate_args('__constructor__', [arg for arg in constructor['inputs']], value=False)

                _, _, computation = chain.call_function(
                    constants.CREATE_CONTRACT_ADDRESS, 
                    decode_hex(desc['evm']['bytecode']['object']), 
                    call
                )

                chain.log_function_call(f"constructor {contract_name}", call['pk'], call['args'], call['value'], computation.get_gas_used())

                contract_address = computation.msg.storage_address

                chain.contracts[contract_address] = {}

                for abi in desc['abi']:
                    if abi['type'] != 'function':
                        continue
                    fname = abi['name']
                    fin = [inp for inp in abi['inputs']]
                    fout = [out for out in abi['outputs']]
                    chain.contracts[contract_address][fname] = {
                        'in': fin,
                        'out': fout,
                        'payable': abi['payable']
                    }
                
                logging.info(" Compilation gas estimates:")

                for function, fhash in desc['evm']['methodIdentifiers'].items():
                    fname = function.split("(")[0]
                    chain.contracts[contract_address][fname]['hash'] = decode_hex(fhash)
                    chain.contracts[contract_address][fname]['compilation_estimate'] = desc['evm']['gasEstimates']['external'][function]

                    function_signature = f"{function} => ({', '.join(arg['type'] for arg in chain.contracts[contract_address][fname]['out'])})"

                    logging.info(f" {function_signature}: {desc['evm']['gasEstimates']['external'][function]}{' payable' if chain.contracts[contract_address][fname]['payable'] else ''}")
                    chain.fuzzing_data.set_expected_cost(fname, desc['evm']['gasEstimates']['external'][function])

        block = chain.get_vm().finalize_block(chain.get_block())

        nonce, mix_hash = mine_pow_nonce(
            block.number,
            block.header.mining_hash,
            block.header.difficulty
        )

        chain.mine_block(mix_hash=mix_hash, nonce=nonce)

        return chain

    def fuzz(self, log = None):
        '''Mines a block, executing a number of transactions to fuzz the contracts being tested.
        '''
        for _ in range(self.txs):
            contract_address = choice(list(self.contracts))
            function_name = choice(list(self.contracts[contract_address]))

            function_hash = self.contracts[contract_address][function_name]['hash']
            call = self.fuzzer.generate_args(
                function_name, 
                [arg for arg in self.contracts[contract_address][function_name]['in']], 
                value=self.contracts[contract_address][function_name]['payable']
            )

            _, _, computation = self.call_function(contract_address, function_hash, call)

            self.log_function_call(function_name, call['pk'], call['args'], call['value'], computation.get_gas_used())
            out_types = [arg['type'] for arg in self.contracts[contract_address][function_name]['out']]
            try: 
                computation.raise_if_error()
                logging.info(f" Returned value: {decode_abi(out_types, computation.output)}")
            except Revert as r:
                logging.info(f" Call reverted. {r.args[0]}")
            except VMError as e:
                logging.info(f" Call resulted in error: {e}")
            except Exception as e:
                logging.info(f" Something went wrong while decoding the output. {e}")
        

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
            nonce = nonce,
            gas_price = 0,
            gas = 1000000,
            to = to,
            value = call['value'],
            data = b''.join([function_hash, call['data']])
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

    def log_function_call(self, fname, pk, primitive_args, value, gas_used):
        logging.info(
            f''' 
            FUNCTION CALL: {fname} ({", ".join(f"{_type} {name}: {value}" for name, _type, value in primitive_args)})
                CALLER: 0x{pk.hex()} 
                VALUE: {value} 
                GAS SPENT: {gas_used}''')

        self.fuzzing_data.register_call(fname, gas_used)
