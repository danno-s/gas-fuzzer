from random import randint, choice, getrandbits

from decimal import Decimal

from string import printable

from .base import BaseTypeFuzzer

class UIntFuzzer(BaseTypeFuzzer):
    def __init__(self, bits, **kwargs):
        assert bits % 8 == 0 and 0 < bits <= 256, f"invalid bit number {bits} for type uint"
        self.bits = bits
        super().__init__(**kwargs)

    def __call__(self):
        return randint(0, 2 ** self.bits - 1)

    def __str__(self):
        return "uint"

    def get_names(self):
        if self.bits == 256:
            yield str(self)
        yield f"{str(self)}{self.bits}"

class IntFuzzer(UIntFuzzer):
    def __init__(self, bits, **kwargs):
        super().__init__(bits, **kwargs)

    def __call__(self):
        return randint(-2 ** (self.bits - 1), 2 ** (self.bits - 1) - 1)

    def __str__(self):
        return "int"

class AddressFuzzer(UIntFuzzer):
    def __init__(self, **kwargs):
        super().__init__(160, **kwargs)

    def __str__(self):
        return "address"

    def __call__(self):
        return super().__call__().to_bytes(length=20, byteorder='big')

class BoolFuzzer(BaseTypeFuzzer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __call__(self):
        return choice([True, False])

    def __str__(self):
        return "bool"

class UFixedFuzzer(BaseTypeFuzzer):
    def __init__(self, m_bits, n_bits, **kwargs):
        assert 8 <= m_bits <= 256 and m_bits % 8 == 0, f"invalid bit number {m_bits} for type ufixed"
        assert 0 < n_bits <= 80, f"invalid exponent {n_bits} for type ufixed"
        self.m_bits = m_bits
        self.n_bits = n_bits
        super().__init__(**kwargs)

    def __call__(self):
        return Decimal(randint(0, 2 ** self.m_bits - 1)) / Decimal(10 ** self.n_bits)

    def __str__(self):
        return "ufixed"

    def get_names(self):
        if self.m_bits == 128 and self.n_bits == 18:
            yield str(self)
        yield f"{str(self)}{self.m_bits}x{self.n_bits}"

        
class FixedFuzzer(UFixedFuzzer):
    def __init__(self, m_bits, n_bits, **kwargs):
        super().__init__(**kwargs)

    def __call__(self):
        return Decimal(randint(-2 ** (self.m_bits - 1), 2 ** (self.m_bits - 1) - 1)) / Decimal(10 ** self.n_bits)

    def __str__(self):
        return "fixed"
        
class BytesFuzzer(BaseTypeFuzzer):
    def __init__(self, byte_n, **kwargs):
        assert 0 < byte_n <= 32, f"invalid bit number {byte_n} for type bytes"
        self.byte_n = byte_n
        super().__init__(**kwargs)

    def __call__(self):
        return bytearray(getrandbits(8) for _ in range(self.byte_n))

    def __str__(self):
        return f"bytes{self.byte_n}"

class FunctionFuzzer(BytesFuzzer):
    def __init__(self, **kwargs):
        super().__init__(24, **kwargs)

    def __str__(self):
        return "function"

class ArrayFuzzer(BaseTypeFuzzer):
    def __init__(self, m, subtype, **kwargs):
        from .utils import fuzzer_from_type
        self.m = m
        self.subfuzzer = fuzzer_from_type(subtype, **kwargs)
        super().__init__(**kwargs)

    def __call__(self):
        return [self.subfuzzer() for _ in range(self.m)]

    def __str__(self):
        return f"{str(self.subfuzzer)}[{self.m}]"

class CharFuzzer(BaseTypeFuzzer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __call__(self):
        return choice(printable)