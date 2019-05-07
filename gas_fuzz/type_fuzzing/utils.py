from re import search

from .primitive_types import (
    UIntFuzzer, 
    IntFuzzer,
    AddressFuzzer,
    UFixedFuzzer,
    FixedFuzzer,
    BytesFuzzer,
    BoolFuzzer,
    FunctionFuzzer,
    ArrayFuzzer
)

from .dynamic_types import (
    DynamicArrayFuzzer,
    DynamicBytesFuzzer,
    StringFuzzer,
    TupleFuzzer
)

def fuzzer_from_type(_type, **kwargs):
    '''Given a valid EVM primitive type, return an instance of a fuzzer of the given type
    '''
    # Check for special, recursive cases first
    
    # Tuples
    m = search(r"\((?P<types>[^,]+(,[^,]+)*)\)", _type)
    if m:
        return TupleFuzzer(m.group('types').split(','), **kwargs)
    
    # Arrays
    m = search(r"(?P<type>.*)\[(?P<number>\d*)\]", _type)
    if m:
        # Statically sized array
        if m.group('number'):
            return ArrayFuzzer(m.group('number'), m.group('type'), **kwargs)
        # Dynamic sized array
        return DynamicArrayFuzzer(m.group('type'), **kwargs)

    # uint and int
    m = search(r"(?P<unsigned>u)?int(?P<bits>\d*)", _type)
    if m:
        bits = int(m.group('bits')) if m.group('bits') else 256
        # uint
        if m.group('unsigned'):
            return UIntFuzzer(bits, **kwargs)
        # int
        return IntFuzzer(bits, **kwargs)

    # ufixed and fixed
    m = search(r"(?P<unsigned>u)?fixed((?P<m_bits>\d+)x(?P<n_bits>\d+))?", _type)
    if m:
        m_bits = int(m.group('m_bits')) if m.group('m_bits') else 128
        n_bits = int(m.group('n_bits')) if m.group('n_bits') else 18
        # ufixed
        if m.group('unsigned'):
            return UFixedFuzzer(m_bits, n_bits, **kwargs)
        # fixed
        return FixedFuzzer(m_bits, n_bits, **kwargs)

    # bytes
    m = search(r"bytes(?P<byte_n>\d*)", _type)
    if m:
        if m.group('byte_n'):
            return BytesFuzzer(int(m.group('byte_n')), **kwargs)
        return DynamicBytesFuzzer(**kwargs)

    # string
    if _type == "string":
        return StringFuzzer(**kwargs)

    # address
    if _type == "address":
        return AddressFuzzer(**kwargs)

    # bool
    if _type == "bool":
        return BoolFuzzer(**kwargs)

    # function
    if _type == "function":
        return FunctionFuzzer(**kwargs)
