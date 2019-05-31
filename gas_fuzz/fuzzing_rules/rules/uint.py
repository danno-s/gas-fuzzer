from . import BaseFuzzerRule

from random import randint

class UIntLimits(BaseFuzzerRule):
    def __init__(self, rules, fuzzer):
        from type_fuzzing import UIntFuzzer
        assert isinstance(fuzzer, UIntFuzzer)
        super().__init__(rules, fuzzer)
        self.min = rules["min"]
        self.max = rules["max"]

    def validate_rules(self, rules):
        assert "min" in rules, "limit rules must have a min argument"
        assert "max" in rules, "limit rules must have a max argument"
        assert rules["min"] > 0, f"{self.fuzzer} value cannot be lower than 0"
        assert rules["max"] < 2 ** self.fuzzer.bits - 1, f"{self.fuzzer} value cannot be higher than {2 ** self.fuzzer.bits - 1}"

    def __call__(self):
        return randint(self.min, self.max)
