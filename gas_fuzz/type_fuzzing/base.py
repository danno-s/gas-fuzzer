from parsing.instantiators import instantiate_rules, instantiate_selector
from fuzzing_rules.rules import BaseFuzzerRule
from fuzzing_rules.selectors import BaseRuleSelector

class BaseTypeFuzzer():
    def __init__(self, rules=None, selector=None):
        self.rules = instantiate_rules(rules) if rules is not None else [BaseFuzzerRule(self)]
        self.selector = instantiate_selector(selector) if selector is not None else BaseRuleSelector(self.rules)

    def __call__(self):
        # Select a rule, and delegate the generation to it.
        return self.selector()()

    def __str__(self):
        """Prints the solidity type this fuzzer generates"""
        raise NotImplementedError("Subclasses must override __str__")

    def validate(self, value):
        """Validates a value generated by a rule"""
        raise NotImplementedError("Subclasses must override validate")

    def next(self, value):
        """Generates a new random value, without any generation rules"""
        raise NotImplementedError("Subclasses must override next")