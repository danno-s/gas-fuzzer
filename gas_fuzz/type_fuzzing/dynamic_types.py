from .base import BaseTypeFuzzer

from .primitive_types import (
    ArrayFuzzer,
    BytesFuzzer,
    CharFuzzer
)

from random import expovariate

class DynamicLengthFuzzer(BaseTypeFuzzer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(self, value):
        return value

    def get_length(self):
        return int(expovariate(1 / 64)) + 1

class DynamicArrayFuzzer(ArrayFuzzer, DynamicLengthFuzzer):
    def __init__(self, subtype, **kwargs):
        super().__init__(1, subtype, **kwargs)

    def validate(self, value):
        return value

    def next(self):
        self.m = self.get_length()
        return super().next()

    def __str__(self):
        return f"{str(self.subfuzzer)}[]"

class DynamicBytesFuzzer(BytesFuzzer, DynamicLengthFuzzer):
    def __init__(self, **kwargs):
        super().__init__(1, **kwargs)

    def validate(self, value):
        return value

    def next(self):
        self.byte_n = self.get_length()
        return super().next()
        
    def __str__(self):
        return "bytes"

class StringFuzzer(CharFuzzer, DynamicLengthFuzzer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(self, value):
        return value

    def next(self):
        return ''.join(super(StringFuzzer, self).next() for _ in range(self.get_length()))
        
    def __str__(self):
        return "string"

class TupleFuzzer(BaseTypeFuzzer):
    def __init__(self, *types, **kwargs):
        from .utils import fuzzer_from_type
        super().__init__(**kwargs)
        self.subfuzzers = [fuzzer_from_type(_type, **kwargs) for _type in types]

    def validate(self, value):
        return value

    def next(self):
        return [fuzzer() for fuzzer in self.subfuzzers]

    def __str__(self):
        return f"({','.join(str(fuzzer) for fuzzer in self.subfuzzers)})"