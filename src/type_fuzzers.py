from random import randint, choice, choices, getrandbits
from decimal import Decimal
from re import search

from string import printable

def uint_fuzzer(bits):
    assert bits % 8 == 0 and 0 < bits <= 256, f"invalid bit number {bits} for type uint"
    def uint_b_fuzzer():
        return randint(0, 2 ** bits - 1)
    return uint_b_fuzzer

def int_fuzzer(bits):
    assert bits % 8 == 0 and 0 < bits <= 256, f"invalid bit number {bits} for type int"
    def int_b_fuzzer():
        return randint(-2 ** (bits - 1), 2 ** (bits - 1) - 1)
    return int_b_fuzzer

def address_fuzzer():
    return uint_fuzzer(160)().to_bytes(length=20, byteorder='big')

def bool_fuzzer():
    return choice([True, False])

def fixed_fuzzer(m_bits, n_bits):
    assert 8 <= m_bits <= 256 and m_bits % 8 == 0, f"invalid bit number {m_bits} for type fixed"
    assert 0 < n_bits <= 80, f"invalid exponent {n_bits} for type fixed"
    def fixed_n_fuzzer():
        return Decimal(randint(-2 ** (m_bits - 1), 2 ** (m_bits - 1) - 1)) / Decimal(10 ** n_bits)
    return fixed_n_fuzzer

def ufixed_fuzzer(m_bits, n_bits):
    assert 8 <= m_bits <= 256 and m_bits % 8 == 0, f"invalid bit number {m_bits} for type fixed"
    assert 0 < n_bits <= 80, f"invalid exponent {n_bits} for type fixed"
    def fixed_n_fuzzer():
        return Decimal(randint(0, 2 ** m_bits - 1)) / Decimal(10 ** n_bits)
    return fixed_n_fuzzer

def bytes_fuzzer(byte_n):
    assert 0 < byte_n <= 32, f"invalid bit number {byte_n} for type bytes"
    def byte_n_fuzzer():
        return bytearray(getrandbits(8) for _ in range(byte_n))
    return byte_n_fuzzer()

def function_fuzzer():
    return bytes_fuzzer(24)

type_fuzzers = {
    'uint': uint_fuzzer(256),
    'int': int_fuzzer(256),
    'address': address_fuzzer,
    'bool': bool_fuzzer,
    'ufixed': ufixed_fuzzer(128, 18),
    'fixed': fixed_fuzzer(128, 18),
    'function': function_fuzzer
}

# Add all variants of uint and int
for m in range(8, 257, 8):
    type_fuzzers[f'uint{m}'] = uint_fuzzer(m)
    type_fuzzers[f'int{m}'] = int_fuzzer(m)

# Add all variants of fixed and ufixed
for m in range(8, 257, 8):
    for n in range(1, 81):
        type_fuzzers[f'fixed{m}x{n}'] = fixed_fuzzer(m, n)
        type_fuzzers[f'ufixed{m}x{n}'] = ufixed_fuzzer(m, n)

# Add all variants of bytes
for m in range(1, 33):
    type_fuzzers[f'bytes{m}'] = bytes_fuzzer(m)

def array_fuzzer(_type, m):
    assert 0 < m, "array length cant be 0"
    fuzzer = get_fuzzer(_type)
    def array_type_m_fuzzer():
        return [fuzzer() for _ in range(m)]
    return array_type_m_fuzzer

MAX_DYNAMIC_SIZE = 1024
p = 1 / 100
GEOMETRIC_DIST = [(1 - p) ** (k - 1) * p for k in range(1, MAX_DYNAMIC_SIZE)]

def get_size():
    return choices(range(1, MAX_DYNAMIC_SIZE), GEOMETRIC_DIST)[0]

def dynamic_bytes_fuzzer():
    return bytearray(getrandbits(8) for _ in range(get_size()))

def dynamic_string_fuzzer():
    return ''.join(choice(printable) for _ in range(get_size()))

def dynamic_array_fuzzer(_type):
    return array_fuzzer(_type, get_size())

type_fuzzers['bytes'] = dynamic_bytes_fuzzer()
type_fuzzers['string'] = dynamic_string_fuzzer()

def tuple_fuzzer(types):
    return [get_fuzzer(_type) for _type in types]

def get_fuzzer(_type):
    try:
        return type_fuzzers[_type]
    except KeyError:
        # Check for special cases
        # Tuples
        m = search(r"\((?P<types>[^,]+(,[^,]+)*)\)", _type)
        if m:
            return tuple_fuzzer(m.group('types').split(','))
        # Arrays
        m = search(r"(?P<type>u?int\d*|address|bool|u?fixed(\d*x\d*)?|bytes\d*|function|\(([^,]+(,[^,]+)*)\))\[(?P<number>\d*)\]", _type)
        if m:
            # Dynamic sized array
            if m.group('number') == '':
                return dynamic_array_fuzzer(m.group('type'))
            # Statically sized array
            return array_fuzzer(m.group('type'), m.group('number'))
