from .base import BaseFuzzerRule

class Constant(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.value = rules["value"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "value")

    def valid_for(self, value):
        return value == self.value

    def next(self):
        return self.value

    def __str__(self):
        return f"Constant ({self.value})"

class NotEqual(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.value = rules["value"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "value")

    def valid_for(self, value):
        return value != self.value

    def __str__(self):
        return f"Not Equal ({self.value})"
