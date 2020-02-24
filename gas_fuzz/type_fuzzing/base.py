from parsing.instantiators import instantiate_rules
from exceptions import InvalidLogicException
from random import choice
import logging

class BaseTypeFuzzer():
    def __init__(self, rules=None, rule_closures=None, argname=None, contract_state_vars=[], **kwargs):
        self.rules = instantiate_rules(rules, str(self), self) if rules is not None else []
        possible_rules = [closure(self, **kwargs) for closure in rule_closures]
        self.rules += [rule for rule in possible_rules if argname in rule.related_args]
        self.rules.sort(key=lambda rule: rule.loc)

        self.argname = argname
        
        # List of values to avoid
        self._except = []

        # If the value is requested to equal some constant
        self.constant = None

        # Delay the application to the fuzzer to accurately point out impossible logical constraints
        self.apply_rules()


    def avoid(self, value):
        '''Add value to the list of forbidden values for this fuzzer
        '''
        if value not in self._except:
            self._except += [value]

    def only(self, value):
        '''Set this fuzzer to only generate a constant
        '''
        if self.constant is None:
            self.constant = value

    def empty_set(self):
        # x != b followed by x == b
        return self.constant is not None and self.constant() in self._except

    def apply_rules(self):
        for rule in self.rules:
            rule.apply_to(self)
            if self.empty_set():
                logging.error(f"\tConstraints applied to fuzzer {self} are impossible to satisfy. The rule that caused this was {rule}.")
                raise InvalidLogicException(self.constraints_to_str())

    def next_valid(self):
        value = self.next()

        logging.debug(f"Fuzzer ({self.pretty_str()}) generated value {value}.")

        # Throws if invalid
        self.validate(value)

        return value

    def pretty_str(self):
        return f"{self} {self.argname}"

    def constraints_to_str(self):
        """Prints the solidity type this fuzzer generates"""
        return """
        Constant value: {self.constant}
        Avoided values: {self._except}"""

    def __str__(self):
        """Prints the solidity type this fuzzer generates"""
        raise NotImplementedError(f"Subclass {type(self).__name__} must override __str__")

    def validate(self, value):
        """Validates a value generated by a rule"""
        raise NotImplementedError(f"Subclass {type(self).__name__} must override validate")
    
    def next(self):
        """Generates a new random value, without any generation rules"""
        raise NotImplementedError(f"Subclass {type(self).__name__} must override next")
