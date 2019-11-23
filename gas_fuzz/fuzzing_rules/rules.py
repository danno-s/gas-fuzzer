from random import randint

class BaseFuzzerRule():
    def __init__(self, rule, fuzzer=None, loc=0):
        self.fuzzer = fuzzer
        self.validate_rules(rule)

        self.loc = loc

    def valid_for(self, values):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override valid_for")

    def validate_rules(self, rule):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override validate_rules")

    def __str__(self):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override __str__")
    
    def validate_args(self, rules, *args):
        for arg in args:
            assert arg in rules, f"{type(self).__name__} rules must have a {arg} argument"

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
