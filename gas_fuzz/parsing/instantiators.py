def instantiate_rules(rules, _type, fuzzer):
    return [instantiate_rule(rule, _type, fuzzer) for rule in rules]

def instantiate_rule(rule, _type, fuzzer):
    from .mappings import rules as rule_map
    return rule_map[rule["rule-type"]](rule, fuzzer)
