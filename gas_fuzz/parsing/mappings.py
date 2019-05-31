from fuzzing_rules.rules import *
from re import search

def rules_from_type(_type):
    '''Given a valid EVM primitive type, return a mapping of rules for that type
    '''
    # Check for special, recursive cases first
    
    # Tuples
    m = search(r"\((?P<types>[^,]+(,[^,]+)*)\)", _type)
    if m:
        return tuple_rules
    
    # Arrays
    m = search(r"(?P<type>.*)\[(?P<number>\d*)\]", _type)
    if m:
        # Statically sized array
        if m.group('number'):
            return array_rules
        # Dynamic sized array
        return dynamic_array_rules

    # uint and int
    m = search(r"(?P<unsigned>u)?int(?P<bits>\d*)", _type)
    if m:
        bits = int(m.group('bits')) if m.group('bits') else 256
        # uint
        if m.group('unsigned'):
            return uint_rules
        # int
        return int_rules

    # ufixed and fixed
    m = search(r"(?P<unsigned>u)?fixed((?P<m_bits>\d+)x(?P<n_bits>\d+))?", _type)
    if m:
        m_bits = int(m.group('m_bits')) if m.group('m_bits') else 128
        n_bits = int(m.group('n_bits')) if m.group('n_bits') else 18
        # ufixed
        if m.group('unsigned'):
            return ufixed_rules
        # fixed
        return fixed_rules

    # bytes
    m = search(r"bytes(?P<byte_n>\d*)", _type)
    if m:
        if m.group('byte_n'):
            return bytes_rules
        return dynamic_bytes_rules

    # string
    if _type == "string":
        return string_rules

    # address
    if _type == "address":
        return address_rules

    # bool
    if _type == "bool":
        return bool_rules

    # function
    if _type == "function":
        return functions_rules

tuple_rules = {}

array_rules = {}

dynamic_array_rules = {}

uint_rules = {
    "limits": UIntLimits
}

int_rules = {}

ufixed_rules = {}

fixed_rules = {}

bytes_rules = {}

dynamic_bytes_rules = {}

string_rules = {}

address_rules = {}

bool_rules = {}

functions_rules = {}


selectors = {

}