from .base import BaseFuzzerRule
from eth_abi import encode_single, decode_abi

from pprint import pprint

class Constant(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.value = rules["value"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "value")

    def valid_for(self, value):
        return value == self.value

    def next(self):
        return self.value

    def __str__(self):
        return f"Constant ({self.value})"

class NotEqual(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.value = rules["value"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "value")

    def valid_for(self, value):
        return value != self.value

    def __str__(self):
        return f"Not Equal ({self.value})"

class FunctionCall(BaseFuzzerRule):
    '''This constraints calls a function in the chain and evaluates its result.
    This means the constraint takes into account the current contract state. (!)

    Many different kinds of function calls can generate this constraint. In particular,
    two cases can be distinguished.

    Base case:
        A function call like `f()` will generate a no-argument function, that simply 
        generates a call to the contract to compute the value.

    Inductive case:
        A function call like `g(f())` will generate a function that recursively generates
        another constraint that computes `f()`.

    It is important to note that, in solidity, the generated AST includes _public functions_
    that provide an interface to a contracts variables. This means that this constraint is 
    also responsible for observing contracts variables. So this allows for validation of statements 
    like:
        require(contract_property == 0) => Constant -> FunctionCall

    Or even:
        require(is_even(contract_property)) => FunctionCall -> FunctionCall

    And a more complex example:
        require(contract_property_a == contract_proprty_b) => Equal -> FunctionCall
                                                                    -> FunctionCall
    '''
    def __init__(self, 
                 rules,
                 chain_fuzzer=None,
                 contract=None,
                 contract_address=None,
                 callback=None,
                 args=None,
                 **kwargs
                ):
        super().__init__(rules, **kwargs)
        self.name = rules["name"]
        self.contract_address = contract_address
        self.function_hash = chain_fuzzer.contracts[contract]['functions'][rules["name"]]['hash']
        self.callback = callback
        self.get_account = chain_fuzzer.get_account
        self.args = chain_fuzzer.contracts[contract]['functions'][rules["name"]]['args']
        self.out = chain_fuzzer.contracts[contract]['functions'][rules["name"]]['out']

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "name")

    def valid_for(self, value):
        sk, pk = self.get_account()

        call = {
            'sk': sk,
            'pk': pk,
            'value': 0,
            'data': b''
        }

        # To evaluate, call the function with the given arguments.
        _block, _receipt, computation = self.callback(
            self.contract_address,
            self.function_hash,
            call
        )

        return decode_abi(self.out, computation.output)[0]

    def __str__(self):
        return f"Function Call ({self.name})"
