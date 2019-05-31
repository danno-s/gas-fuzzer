def parse_rules(rules, contract, function, _type):
    type_object = pipeline(
        rules,
        find(contract),
        find(function),
        find_strict(_type)
    )

    try:
        return (
            type_object["rules"],
            type_object["selector"] if "selector" in type_object else None
        ) if type_object is not None else (None, None)
    except KeyError:
        raise InvalidRuleError("Types must define rules when declared.")

def find(name):
    def find_object_wildcard(object):
        # Search by name
        if name in object:
            return object[name]
        # Search by wildcard
        if "*" in object:
            return object["*"]
        return None
    return find_object_wildcard

def find_strict(name):
    def find_object(object):
        # Search by name
        if name in object:
            return object[name]
        return None
    return find_object

def bind(value, function):
    return None if value is None else function(value)

def pipeline(e, *functions):
    for f in functions:
        e = bind(e, f)
    return e

class InvalidRuleError(Exception):
    """Thrown when an invalid rule file is passed"""
    pass