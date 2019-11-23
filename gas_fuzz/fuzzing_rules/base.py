from random import randint

class BaseFuzzerRule():
    def __init__(self, rule, fuzzer=None, loc=0):
        self.fuzzer = fuzzer
        self.validate_rules(rule)

        self.loc = loc

    def valid_for(self, values):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override valid_for")

    def validate_rules(self, rule):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override validate_rules")

    def __str__(self):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override __str__")
    
    def validate_args(self, rules, *args):
        for arg in args:
            assert arg in rules, f"{type(self).__name__} rules must have a {arg} argument"
