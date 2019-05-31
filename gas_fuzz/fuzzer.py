from eth_abi import encode_single
from eth_keys import keys
from eth_typing import Address

from type_fuzzing.utils import fuzzer_from_type
from rule_parser import parse_rules

from random import random, randint, choice
import json

from pprint import pprint

class SolidityFuzzer():
    def __init__(self,
                 faucet_callback,
                 faucet_sk = None,
                 new_account_chance = 0.25, 
                 max_balance = 1000,
                 rules = None):
        self.max_balance = max_balance
        
        self.rules = None
        if rules:
            with open(rules) as rule_file:
                self.rules = json.load(rule_file)
        
        pprint(self.rules)

        self.faucet_sk = faucet_sk
        self.type_fuzzers = {}
        self.prob = {
            'new_account': new_account_chance
        }

        self.faucet_callback = faucet_callback
        
        self.accounts = []

        self.balances = {}

        self.new_account()

    def generate_args(self, contract, function, args, value=True):
        sk, pk = self.get_account()
        primitive_args = [
            (
                arg['name'], 
                arg['type'], 
                self.fuzz_arg(contract, function, arg['type'])
            ) for arg in args
        ]

        return {
            'sk': sk,
            'pk': pk,
            'value': self.randvalue(pk) if value else 0,
            'args': primitive_args,
            'data': b''.join(encode_single(_type, arg) for _, _type, arg in primitive_args)
        }

    def fuzz_arg(self, contract, function, _type):
        # Load fuzzers dynamically based on the given type
        if _type not in self.type_fuzzers:
            rules, selector = parse_rules(self.rules, contract, function, _type)
            self.type_fuzzers[_type] = fuzzer_from_type(_type, rules=rules, selector=selector)

        return self.type_fuzzers[_type]()

    def get_account(self):
        if random() < self.prob['new_account']:
            return self.new_account()
        return choice(self.accounts)

    def new_account(self):
        while True:
            sk = keys.PrivateKey(randint(1, 2 ** 32 - 1).to_bytes(32, byteorder='big'))

            breakable = not sk == self.faucet_sk
            for ac_sk, _ in self.accounts:
                breakable = breakable and not ac_sk == sk

            if breakable:
                break

        pk = Address(sk.public_key.to_canonical_address())

        account = (sk, pk)
        self.accounts.append(account)

        self.balances[pk] = randint(0, self.max_balance)
        
        self.faucet_callback(pk, self.balances[pk])

        return account

    def randvalue(self, pk):
        value = randint(0, self.balances[pk]) 
        self.balances[pk] -= value
        return value

