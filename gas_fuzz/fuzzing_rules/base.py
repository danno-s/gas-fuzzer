from random import randint

class BaseFuzzerRule():
    def __init__(self, rule, fuzzer=None, loc=0, related_args=[], **kwargs):
        self.related_args = related_args

        assert self.applicable_to(fuzzer), f"Subclass {type(self).__name__} is not applicable to type fuzzer {type(fuzzer).__name__}"

        self.loc = loc

    def applicable_to(self, type_fuzzer):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override applicable_to")

    def apply_to(self, type_fuzzer):
        raise NotImplementedError(f"Subclass {type(self).__name__} must override apply_to")
