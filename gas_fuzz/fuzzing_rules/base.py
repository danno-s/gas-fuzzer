from random import randint

class BaseFuzzerRule():
    def __init__(self, rule, fuzzer=None, loc=0, related_args=[], **kwargs):
        self.fuzzer = fuzzer
        self.validate_rules(rule)
        self.related_args = related_args

        self.loc = loc

    def valid_for(self, values):
        '''This is only called for root-level rules.
        '''
        raise NotImplementedError(f"Subclass {type(self).__name__} must override valid_for")

    def validate_rules(self, rule):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override validate_rules")

    def __str__(self):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override __str__")
    
    def validate_args(self, rules, *args):
        for arg in args:
            assert arg in rules, f"{type(self).__name__} rules must have a {arg} argument"
