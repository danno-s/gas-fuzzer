class BaseFuzzerRule():
    def __init__(self, fuzzer):
        self.fuzzer = fuzzer

    def __call__(self):
        return self.fuzzer.next()