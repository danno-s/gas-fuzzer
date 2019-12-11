from eth_abi import encode_single
from eth_keys import keys
from eth_typing import Address

from type_fuzzing.utils import fuzzer_from_type
from parsing.rule_parser import parse_rules

from random import random, randint, choice
import json

from pprint import pprint

import logging


class SolidityFuzzer():
    def __init__(self,
                 faucet_callback,
                 faucet_sk=None,
                 new_account_chance=0.25,
                 max_balance=1000,
                 rules=None):
        self.max_balance = max_balance

        self.rules = None
        if rules:
            with open(rules) as rule_file:
                self.rules = json.load(rule_file)

        self.contracts = {}
        self.faucet_sk = faucet_sk
        self.type_fuzzers = {}

        self.prob = {
            'new_account': new_account_chance
        }

        self.faucet_callback = faucet_callback

        self.accounts = []

        self.balances = {}

        self.new_account()

    def register_contract(self, contract_name, variables):
        self.contracts[contract_name] = {
            'variables': [var for var in variables],
            'functions': {},
        }

    def set_contract_address(self, contract_name, address):
        self.contracts[contract_name]['address'] = address

    def register_function(self, contract_name, function_name, parameters, constraints):
        print(f"Registering {contract_name}.{function_name}")

        self.contracts[contract_name]['functions'][function_name] = {
            'parameters': [par for par in parameters],
            'constraints': constraints
        }
    
    def set_function_hash(self, contract_name, function_name, f_hash):
        self.contracts[contract_name]['functions'][function_name]['hash'] = f_hash
    
    def set_mutability(self, contract_name, function_name, mut):
        self.contracts[contract_name]['functions'][function_name]['mutable'] = mut

    def set_out(self, contract_name, function_name, out):
        self.contracts[contract_name]['functions'][function_name]['out'] = out

    def set_args(self, contract_name, function_name, args):
        fxs = self.contracts[contract_name]['functions']

        if function_name not in fxs:
            fxs[function_name] = {}

        fxs[function_name]['args'] = args


    def generate_args(self, contract, function, args, value=True):
        sk, pk = self.get_account()

        primitive_args = [
            (
                arg['name'],
                arg['type'],
                self.fuzz_arg(contract, function, arg['type'], arg['name'])
            ) for arg in args
        ]
        
        return {
            'sk': sk,
            'pk': pk,
            'value': self.randvalue(pk) if value else 0,
            'args': primitive_args,
            'data': b''.join(encode_single(_type, arg) for _, _type, arg in primitive_args)
        }

    def fuzz_arg(self, contract, function, _type, name):
        # Load fuzzers dynamically based on the given type
        if not self.get_type_fuzzer(contract, function, _type, name):
            logging.info(
                f" Assigning rules for {contract}.{function} ({_type} {name})")
            rules = parse_rules(self.rules, contract, function, _type)
            logging.info(
                f" Rules: {(', '.join(rule['rule-type'] for rule in rules) if rules is not None else None)}")

            fuzzer = fuzzer_from_type(
                _type,
                rules=rules,
                rule_closures=self.contracts[contract]['functions'][function]['constraints'],
                argname=name,
                # Assume all function calls will be within the same contract.
                contract=contract,
                contract_address=self.contracts[contract]['address'],
                chain_fuzzer=self
            )

            self.add_type_fuzzer(contract, function, _type, name, fuzzer)

        return self.get_type_fuzzer(contract, function, _type, name)()

    def add_type_fuzzer(self, contract, function, _type, name, fuzzer):
        if contract not in self.type_fuzzers:
            self.type_fuzzers[contract] = {}

        if function not in self.type_fuzzers[contract]:
            self.type_fuzzers[contract][function] = {}

        if _type not in self.type_fuzzers[contract][function]:
            self.type_fuzzers[contract][function][_type] = {}

        has_rules = len(fuzzer.rules) != 0

        print(f'Added fuzzer for {contract}.{function}, argument ({_type} {name}) {"with rules:" if has_rules else ""}')
        for rule in fuzzer.rules:
            print(f'\t{type(rule)}')

        self.type_fuzzers[contract][function][_type][name] = fuzzer

    def get_type_fuzzer(self, contract, function, _type, name):
        try:
            return self.type_fuzzers[contract][function][_type][name]
        except KeyError:
            return None

    def get_account(self):
        if random() < self.prob['new_account']:
            return self.new_account()
        return choice(self.accounts)

    def new_account(self):
        while True:
            sk = keys.PrivateKey(
                randint(1, 2 ** 32 - 1).to_bytes(32, byteorder='big'))

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

    def undo_account(self, account):
        self.accounts.remove(account)
        del self.balances[account[1]]

    def randvalue(self, pk):
        value = randint(0, self.balances[pk])
        self.balances[pk] -= value
        return value
