from random import randint, choice, getrandbits

from decimal import Decimal

from string import printable

from .base import BaseTypeFuzzer

import logging

class UIntFuzzer(BaseTypeFuzzer):
    def __init__(self, bits, **kwargs):
        assert bits % 8 == 0 and 0 < bits <= 256, f"invalid bit number {bits} for type uint"
        self.bits = bits

        # List of values to avoid
        self._except = []

        # If the value is requested to equal some constant
        self.constant = None

        # Lower bound for the generation, inclusive
        self.min = 0

        # Upper bound for the generation, inclusive
        self.max = 2 ** self.bits - 1

        super().__init__(**kwargs)

    def avoid(self, value):
        '''Add value to the list of forbidden values for this fuzzer
        '''
        if value not in self._except:
            self._except += [value]

    def only(self, value):
        '''Set this fuzzer to only generate a constant
        '''
        if self.constant is None:
            self.constant = value

    def greater_than(self, value):
        '''Set this fuzzer to generate values greater than to value
        '''
        self.greater_than_equal(value + 1)
    
    def less_than(self, value):
        '''Set this fuzzer to generate values less than to value
        '''
        self.less_than_equal(value - 1)

    def greater_than_equal(self, value):
        '''Set this fuzzer to generate values greater than or equal to value
        '''
        if self.min < value:
            self.min = value
    
    def less_than_equal(self, value):
        '''Set this fuzzer to generate values less than or equal to value
        '''
        if self.max > value:
            self.max = value

    def empty_set(self):
        # x != b followed by x == b
        if self.constant is not None and self.constant in self._except:
            return True

        # lower and upper bounds passed each other
        if self.max < self.min:
            return True

    def validate(self, value):
        assert value >= 0, f"{self} values must be higher than 0. (got {value})"
        assert value < 2 ** self.bits, f"{self} values must be lower than {2 ** self.bits - 1}. (got {value})"
        return value

    def next(self):
        if self.constant is not None:
            return self.constant

        while True:
            val = randint(self.min, self.max)
            if val not in self._except:
                return val

    def __str__(self):
        return "uint"

    def constraints_to_str(self):
        return f"""{self.pretty_str()}:
        Minimum value: {self.min}
        Maximum value: {self.max}

        Constant value: {self.constant}
        Avoided values: {self._except}"""

    def get_names(self):
        if self.bits == 256:
            yield str(self)
        yield f"{str(self)}{self.bits}"

class IntFuzzer(UIntFuzzer):
    def __init__(self, bits, **kwargs):
        super().__init__(bits, **kwargs)

    def validate(self, value):
        assert value < 2 ** (self.bits - 1), f"{self} values must be lower than {2 ** (self.bits - 1)}. (got {value})"
        assert value >= -2 ** (self.bits - 1), f"{self} values must be greater than {-2 ** (self.bits - 1) - 1}. (got {value})"
        return value

    def next(self):
        return randint(-2 ** (self.bits - 1), 2 ** (self.bits - 1) - 1)

    def __str__(self):
        return "int"

class AddressFuzzer(UIntFuzzer):
    def __init__(self, **kwargs):
        super().__init__(160, **kwargs)

    def validate(self, value):
        return value

    def __str__(self):
        return "address"

    def next(self):
        return super().next().to_bytes(length=20, byteorder='big')

class BoolFuzzer(BaseTypeFuzzer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(self, value):
        assert value in [True, False], f"got {value} non bool type"
        return value

    def next(self):
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

    def validate(self, value):
        return value

    def next(self):
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

    def validate(self, value):
        return value

    def next(self):
        return Decimal(randint(-2 ** (self.m_bits - 1), 2 ** (self.m_bits - 1) - 1)) / Decimal(10 ** self.n_bits)

    def __str__(self):
        return "fixed"
        
class BytesFuzzer(BaseTypeFuzzer):
    def __init__(self, byte_n, **kwargs):
        assert 0 < byte_n <= 32, f"invalid bit number {byte_n} for type bytes"
        self.byte_n = byte_n
        super().__init__(**kwargs)

    def validate(self, value):
        return value

    def next(self):
        return bytearray(getrandbits(8) for _ in range(self.byte_n))

    def __str__(self):
        return f"bytes{self.byte_n}"

class FunctionFuzzer(BytesFuzzer):
    def __init__(self, **kwargs):
        super().__init__(24, **kwargs)

    def validate(self, value):
        return value

    def __str__(self):
        return "function"

class ArrayFuzzer(BaseTypeFuzzer):
    def __init__(self, m, subtype, **kwargs):
        from .utils import fuzzer_from_type
        self.m = m
        self.subfuzzer = fuzzer_from_type(subtype, **kwargs)
        super().__init__(**kwargs)

    def validate(self, value):
        return value

    def next(self):
        return [self.subfuzzer() for _ in range(self.m)]

    def __str__(self):
        return f"{str(self.subfuzzer)}[{self.m}]"

class CharFuzzer(BaseTypeFuzzer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(self, value):
        return value

    def next(self):
        return choice(printable)
