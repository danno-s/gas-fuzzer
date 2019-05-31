class BaseRuleSelector():
    def __init__(self):
        pass

    def __call__(self, rules):
        return rules[0]