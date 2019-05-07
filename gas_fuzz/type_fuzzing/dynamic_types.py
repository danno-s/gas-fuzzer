from .base import BaseTypeFuzzer

from .primitive_types import (
    ArrayFuzzer,
    BytesFuzzer,
    CharFuzzer
)

class DynamicLengthFuzzer(BaseTypeFuzzer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get_length(self):
        raise NotImplementedError()

class DynamicArrayFuzzer(ArrayFuzzer, DynamicLengthFuzzer):
    def __init__(self, subtype, **kwargs):
        super().__init__(0, subtype, **kwargs)

    def __call__(self):
        self.m = self.get_length()
        return super().__call__()

    def __str__(self):
        return f"{str(self.subfuzzer)}[]"

class DynamicBytesFuzzer(BytesFuzzer, DynamicLengthFuzzer):
    def __init__(self, **kwargs):
        super().__init__(0, **kwargs)

    def __call__(self):
        self.byte_n = self.get_length()
        return super().__call__()
        
    def __str__(self):
        return "bytes"

class StringFuzzer(CharFuzzer, DynamicLengthFuzzer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __call__(self):
        return ''.join(super().__call__() for _ in range(self.get_length()))
        
    def __str__(self):
        return "string"

class TupleFuzzer(BaseTypeFuzzer):
    def __init__(self, *types, **kwargs):
        from .utils import fuzzer_from_type
        super().__init__(**kwargs)
        self.subfuzzers = [fuzzer_from_type(_type, **kwargs) for _type in types]

    def __call__(self):
        return [fuzzer() for fuzzer in self.subfuzzers]

    def __str__(self):
        return f"({','.join(str(fuzzer) for fuzzer in self.subfuzzers)})"