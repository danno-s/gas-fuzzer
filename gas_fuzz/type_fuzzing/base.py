class BaseTypeFuzzer():
    def __init__(self, rules=None, selector=None):
        self.rules = rules
        self.selector = selector

    def __call__(self):
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()
