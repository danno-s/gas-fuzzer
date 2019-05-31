from random import randint

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

class Limits(BaseFuzzerRule):
    def __init__(self, rules, fuzzer):
        super().__init__(rules, fuzzer)
        self.min = rules["min"]
        self.max = rules["max"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        assert "min" in rules, "limit rules must have a min argument"
        assert "max" in rules, "limit rules must have a max argument"
        assert rules["min"] > 0, f"{self.fuzzer} value cannot be lower than 0. (got {rules['min']})"
        assert rules["max"] < 2 ** self.fuzzer.bits - 1, f"{self.fuzzer} value cannot be higher than {2 ** self.fuzzer.bits - 1}. (got {rules['max']})"

    def __call__(self):
        return randint(self.min, self.max)
