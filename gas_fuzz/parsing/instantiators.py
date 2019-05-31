from mappings import rules as rule_map, selectors as selector_map

def instantiate_rules(rules):
    return [instantiate_rule(rule) for rule in rules]

def instantiate_rule(rule):
    return rule_map[rule["rule-type"]](rule)

def instantiate_selector(selector):
    return selector_map[selector["selector-type"]](selector)