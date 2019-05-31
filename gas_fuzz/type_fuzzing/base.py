from parsing.instantiators import instantiate_rules, instantiate_selector
from fuzzing_rules.rules import NoneFuzzerRule
from fuzzing_rules.selectors import BaseRuleSelector

class BaseTypeFuzzer():
    valid_rules = []

    def __init__(self, rules=None, selector=None):
        rule_instances = instantiate_rules(rules, str(self), self) if rules is not None else [NoneFuzzerRule(self)]
        self.selector = instantiate_selector(selector) if selector is not None else BaseRuleSelector(rule_instances)

    def __call__(self):
        # Select a rule, and delegate the generation to it.
        return self.selector()()

    def validate_rule(self, rule):
        """Raises an exception if the given rule is not valid for this fuzzer"""
        assert type(rule) in self.valid_rules, f"Fuzzer of type {type(self).__name__} doesn't accept rule of type {type(rule).__name__}"

    def __str__(self):
        """Prints the solidity type this fuzzer generates"""
        raise NotImplementedError("Subclasses must override __str__")

    def validate(self, value):
        """Validates a value generated by a rule"""
        raise NotImplementedError("Subclasses must override validate")
    
    def next(self, value):
        """Generates a new random value, without any generation rules"""
        raise NotImplementedError("Subclasses must override next")