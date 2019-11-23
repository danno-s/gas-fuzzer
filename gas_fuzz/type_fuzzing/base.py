from parsing.instantiators import instantiate_rules
from random import choice
import logging

class BaseTypeFuzzer():
    valid_rules = []

    def __init__(self, rules=None, rule_closures=None, max_attempts=10):
        self.rules = instantiate_rules(rules, str(self), self) if rules is not None else []
        self.rules += [closure(self) for closure in rule_closures]

        self.rules.sort(key=lambda rule: rule.loc)

        self.max_attempts = max_attempts

    def __call__(self):
        # No validation available
        if not self.rules:
            return self.next()

        logging.info("Generating values for fuzzer with rules.")

        ruleset = self.rules.copy()

        while len(ruleset) > 0:
            logging.info(f"Attempting with ruleset: {ruleset}")
            base_rule = ruleset[0]

            # Fuzzer has rules. Try to generate args that satisfy (one) of them.
            for attempt in range(self.max_attempts):
                # Generate the argument, depending on if the rule has knowledge on how to generate good arguments.
                try:
                    values = base_rule.next()
                except AttributeError:
                    values = self.next()

                def validate_recursively(rules):        
                    tested_rule, *others = rules
                    logging.info(f'Testing {values} for fuzzer {self} and rule {tested_rule}')
                    return tested_rule.valid_for(values) and (len(others) == 0 or validate_recursively(others))

                if self.validate(values) and validate_recursively(ruleset):
                    return values
            
            # Remove the last rule and attempt again.
            ruleset.pop()

        logging.warn("Failed to satisfy all rules. Generating a random number without any rules.")
        return self.next()


    def validate_rule(self, rule):
        """Raises an exception if the given rule is not valid for this fuzzer"""
        assert type(rule) in self.valid_rules, f"Fuzzer of type {type(self).__name__} doesn't accept rule of type {type(rule).__name__}"

    def __str__(self):
        """Prints the solidity type this fuzzer generates"""
        raise NotImplementedError(f"Subclass {type(self).__name__} must override __str__")

    def validate(self, value):
        """Validates a value generated by a rule"""
        raise NotImplementedError(f"Subclass {type(self).__name__} must override validate")
    
    def next(self, value):
        """Generates a new random value, without any generation rules"""
        raise NotImplementedError(f"Subclass {type(self).__name__} must override next")
