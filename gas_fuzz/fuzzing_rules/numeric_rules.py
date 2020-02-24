from .base import BaseFuzzerRule

from type_fuzzing import (
    UIntFuzzer,
    IntFuzzer,
    FixedFuzzer,
    UFixedFuzzer
)

import logging

class GreaterThan(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.min = rules["min"]

    def applicable_to(self, fuzzer):
        return type(fuzzer) in [UIntFuzzer, IntFuzzer, FixedFuzzer, UFixedFuzzer]

    def apply_to(self, fuzzer):
        fuzzer.greater_than(self.min)
        
    def __str__(self):
        return f"Greater Than ({self.min})"

class GreaterThanEqual(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.min = rules["min"]

    def applicable_to(self, fuzzer):
        return type(fuzzer) in [UIntFuzzer, IntFuzzer, FixedFuzzer, UFixedFuzzer]

    def apply_to(self, fuzzer):
        fuzzer.greater_than_equal(self.min)
        
    def __str__(self):
        return f"Greater Than Equal ({self.min})"

class LessThan(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.max = rules["max"]

    def applicable_to(self, fuzzer):
        return type(fuzzer) in [UIntFuzzer, IntFuzzer, FixedFuzzer, UFixedFuzzer]

    def apply_to(self, fuzzer):
        fuzzer.less_than(self.max)
        
    def __str__(self):
        return f"Less Than ({self.max})"

class LessThanEqual(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.max = rules["max"]

    def applicable_to(self, fuzzer):
        return type(fuzzer) in [UIntFuzzer, IntFuzzer, FixedFuzzer, UFixedFuzzer]

    def apply_to(self, fuzzer):
        fuzzer.less_than_equal(self.max)
        
    def __str__(self):
        return f"Less Than Equal({self.max})"

class Limits(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        super().__init__(rules, **kwargs)
        self.min = rules["min"]
        self.max = rules["max"]
        
    def __str__(self):
        return f"Limits ({self.min} => {self.max})"
