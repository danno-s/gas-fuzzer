def instantiate_rules(rules, _type, fuzzer):
    return [instantiate_rule(rule, _type, fuzzer) for rule in rules]

def instantiate_rule(rule, _type, fuzzer):
    from .mappings import rules_from_type
    return rules_from_type(_type)[rule["rule-type"]](rule, fuzzer)

def instantiate_selector(selector):
    from .mappings import selectors as selector_map
    return selector_map[selector["selector-type"]](selector)