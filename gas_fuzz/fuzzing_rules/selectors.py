from random import choice

class BaseRuleSelector():
    def __init__(self, rules):
        self.rules = rules

    def __call__(self):
        """
        Return a random rule, as a base case (when no rules 
        are defined, the only rule is a BaseFuzzerRule)
        """
        return choice(self.rules)
