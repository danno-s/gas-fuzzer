from random import randint

class BaseFuzzerRule():
    def __init__(self, rule, fuzzer):
        self.fuzzer = fuzzer
        self.validate_rules(rule)

    def __call__(self):
        raise NotImplementedError("Subclasses of BaseFuzzerRule must implement __call__")

    def validate_rules(self, rule):
        raise NotImplementedError("Subclasses of BaseFuzzerRule must implement validate_rules")
    
    def validate_args(self, rules, *args):
        for arg in args:
            assert arg in rules, f"{type(self).__name__} rules must have a {arg} argument"

class NoneFuzzerRule(BaseFuzzerRule):
    def __init__(self, fuzzer):
        self.fuzzer = fuzzer

    def __call__(self):
        return self.fuzzer.next()

    def validate_rules(self, rules):
        """Rules don't need validation since there are no rules"""
        pass

class Limits(BaseFuzzerRule):
    def __init__(self, rules, fuzzer):
        super().__init__(rules, fuzzer)
        self.min = rules["min"]
        self.max = rules["max"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "min", "max")

    def __call__(self):
        return randint(self.min, self.max)

class Constant(BaseFuzzerRule):
    def __init__(self, rules, fuzzer):
        super().__init__(rules, fuzzer)
        self.value = rules["value"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "value")

    def __call__(self):
        return self.value

