class BaseFuzzerRule():
    def __init__(self, rule, fuzzer):
        self.fuzzer = fuzzer
        self.validate_rules(rule)

    def __call__(self):
        raise NotImplementedError("Subclasses of BaseFuzzerRule must implement __call__")

    def validate_rules(self, rule):
        raise NotImplementedError("Subclasses of BaseFuzzerRule must implement validate_rules")

class NoneFuzzerRule(BaseFuzzerRule):
    def __call__(self):
        return self.fuzzer.next()

    def validate_rules(self, rules):
        """Rules don't need validation since there are no rules"""
        pass