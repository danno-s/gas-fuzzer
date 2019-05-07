from eth import constants
from eth.chains.base import MiningChain
from eth.db.atomic import AtomicDB
from eth.consensus.pow import mine_pow_nonce

from eth_typing import Address
from eth_utils import decode_hex
from eth_keys import keys

from eth_abi import decode_abi, decode_single

from random import choice

from fuzzer import SolidityFuzzer

from pprint import pprint

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

        chain = cls.from_genesis(AtomicDB(), GENESIS_PARAMS)

        chain.fuzzer = SolidityFuzzer(chain, **kwargs)

        # Number of transactions per block
        chain.txs = tx
        
        vm = chain.get_vm()

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

        for _, contracts in standard_output.items():
            for _, desc in contracts.items():
                constructor = [abi for abi in desc['abi'] if abi['type'] == 'constructor'][0]
                call = chain.fuzzer.generate_args('__constructor__', [arg['type'] for arg in constructor['inputs']])

                _, _, computation = chain.call_function(
                    constants.CREATE_CONTRACT_ADDRESS, 
                    decode_hex(desc['evm']['bytecode']['object']), 
                    call
                )

                print(f"Total gas consumed in constructor: {computation.get_gas_used()}")

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
                        'out': fout
                    }

                for function, fhash in desc['evm']['methodIdentifiers'].items():
                    fname = function.split("(")[0]
                    chain.contracts[contract_address][fname]['hash'] = decode_hex(fhash)
                    chain.contracts[contract_address][fname]['compilation_estimate'] = desc['evm']['gasEstimates']['external'][function]

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
            call = self.fuzzer.generate_args(function_name, [arg['type'] for arg in self.contracts[contract_address][function_name]['in']])

            _, _, computation = self.call_function(contract_address, function_hash, call)

            print(f"Total gas used in call of function {function_name}: {computation.get_gas_used()}")
            out_types = [arg['type'] for arg in self.contracts[contract_address][function_name]['out']]
            print(f"Returned value: {[decode_abi(out_types, computation.output)]}")
        

        block = self.get_vm().finalize_block(self.get_block())

        nonce, mix_hash = mine_pow_nonce(
            block.number,
            block.header.mining_hash,
            block.header.difficulty
        )

        self.mine_block(mix_hash=mix_hash, nonce=nonce)

    def call_function(self, to, function_hash, call):
        self.get_vm().state.account_db.set_balance(call['pk'], call['value'])

        nonce = self.get_vm().state.account_db.get_nonce(call['pk'])

        tx = self.get_vm().create_unsigned_transaction(
            nonce = nonce,
            gas_price = 0,
            gas = 1000000,
            to = to,
            value = call['value'],
            data = b''.join([function_hash, call['args']])
        )

        signed_tx = tx.as_signed_transaction(call['sk'])

        return self.apply_transaction(signed_tx)
