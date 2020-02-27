from .base import BaseFuzzerRule
from eth_abi import encode_single, decode_abi

from type_fuzzing import (
    UIntFuzzer
)

from pprint import pprint


class Constant(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        self.value = rules["value"]
        super().__init__(rules, **kwargs)

    def applicable_to(self, fuzzer):
        return fuzzer.validate(self.value)

    def apply_to(self, fuzzer):
        fuzzer.only(self.value)

    def __str__(self):
        return f"Constant ({self.value})"


class NotEqual(BaseFuzzerRule):
    def __init__(self, rules, **kwargs):
        self.value = rules["value"]
        super().__init__(rules, **kwargs)

    def applicable_to(self, fuzzer):
        return fuzzer.validate(self.value)

    def apply_to(self, fuzzer):
        fuzzer.avoid(self.value)

    def __str__(self):
        return f"Not Equal ({self.value})"
