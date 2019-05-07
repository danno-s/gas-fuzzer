from eth_abi import encode_single
from eth_keys import keys
from eth_typing import Address

from type_fuzzing.utils import fuzzer_from_type

from random import random, randint, choice

class SolidityFuzzer():
    def __init__(self, 
                 chain, 
                 new_account_chance=0.25, 
                 max_value = 10 ** 10,
                 rules = None):
        self.max_value = max_value
        self.rules = rules
        self.type_fuzzers = {}
        self.prob = {
            'new_account': new_account_chance
        }
        
        sk = keys.PrivateKey(randint(1, 2 ** 32 - 1).to_bytes(32, byteorder='big'))
        pk = Address(sk.public_key.to_canonical_address())
        
        self.accounts = [
            (sk, pk)
        ]

    def generate_args(self, func, types):
        func_rules = self.rules[func] if self.rules and func in self.rules else None
        sk, pk = self.get_account()
        return {
            'sk': sk,
            'pk': pk,
            'value': randint(0, self.max_value),
            'args': b''.join(self.fuzz_arg(_type, func_rules) for _type in types)
        }

    def fuzz_arg(self, _type, func_rules):
        # Load fuzzers dynamically based on the given type
        if _type not in self.type_fuzzers:
            self.type_fuzzers[_type] = fuzzer_from_type(_type, rules=func_rules)

        return encode_single(_type, self.type_fuzzers[_type]())

    def get_account(self):
        if random() > self.prob['new_account']:
            while True:
                sk = keys.PrivateKey(randint(1, 2 ** 32 - 1).to_bytes(32, byteorder='big'))

                breakable = True
                for ac_sk, _ in self.accounts:
                    breakable = breakable and not ac_sk == sk

                if breakable:
                    break

            pk = Address(sk.public_key.to_canonical_address())

            account = (sk, pk)
            self.accounts.append(account)

            return account
        return choice(self.accounts)

