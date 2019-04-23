from eth import constants
from eth.chains.base import MiningChain
from eth.db.atomic import AtomicDB

from eth_typing import Address
from eth_utils import decode_hex
from eth_keys import keys

class FuzzingChain(MiningChain):
    @classmethod
    def init(cls, contract_bytecodes = [], tx = 10):
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

        # Private key of adress from which all transactions will be sent.
        chain.sk = keys.PrivateKey((1).to_bytes(32, byteorder='big'))
        # Public key of said address.
        chain.pk = Address(chain.sk.public_key.to_canonical_address())

        # Number of transactions per block
        chain.txs = tx
        
        vm = chain.get_vm()

        for bytecode_path in contract_bytecodes:
            nonce = vm.state.account_db.get_nonce(chain.pk)

            with open(bytecode_path) as bytecode:
                tx = vm.create_unsigned_transaction(
                    nonce = nonce,
                    gas_price = 0,
                    gas = 1000000,
                    to = constants.CREATE_CONTRACT_ADDRESS,
                    value = 0,
                    data = decode_hex(bytecode.read())
                )

            signed_tx = tx.as_signed_transaction(chain.sk)

            chain.apply_transaction(signed_tx)

        block = chain.get_vm().finalize_block(chain.get_block())

        # Adresses of all the contracts being tested
        chain.contracts = []



        return chain

    def fuzz(self, n_transactions = 10, log = None):
        '''Mines a block, executing a number of transactions to fuzz the contracts being tested.
        '''
        pass