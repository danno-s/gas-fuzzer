class BaseTypeFuzzer():
    def __init__(self, rules=None):
        self.rules = self.get_rules(rules)

    def __call__(self):
        raise NotImplementedError()

    def get_rules(self, rules):
        if not rules:
            return
            
        for name in self.get_names():
            if name in rules:
                return rules[name]
        return None

    def __str__(self):
        raise NotImplementedError()

    def get_names(self):
        yield str(self)

