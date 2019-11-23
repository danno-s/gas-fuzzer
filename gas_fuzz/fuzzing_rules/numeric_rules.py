from .base import BaseFuzzerRule

class GreaterThan(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.min = rules["min"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "min")

    def valid_for(self, value):
        return value > self.min
        
    def __str__(self):
        return f"Greater Than ({self.min})"

class GreaterThanEqual(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.min = rules["min"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "min")

    def valid_for(self, value):
        return value >= self.min
        
    def __str__(self):
        return f"Greater Than Equal ({self.min})"

class LessThan(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.max = rules["max"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "max")
    
    def valid_for(self, value):
        return value < self.max
        
    def __str__(self):
        return f"Less Than ({self.max})"

class LessThanEqual(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.max = rules["max"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "max")

    def valid_for(self, value):
        return value <= self.max
        
    def __str__(self):
        return f"Less Than Equal({self.max})"

class Limits(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.min = rules["min"]
        self.max = rules["max"]

    def validate_rules(self, rules):
        self.fuzzer.validate_rule(self)
        self.validate_args(rules, "min", "max")

    def valid_for(self, value):
        return self.min <= value and value <= self.max
        
    def __str__(self):
        return f"Limits ({self.min} => {self.max})"
