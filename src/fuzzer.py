from eth_abi import encode_single
from type_fuzzers import get_fuzzer

from random import random


class SolidityFuzzer():
    def __init__(self, seed = None):
        self.seed = seed if seed else random() * 1000000

    def generate_args(self, types):
        return b''.join(self.fuzz_arg(_type) for _type in types)

    def fuzz_arg(self, _type):
        return encode_single(_type, get_fuzzer(_type)())