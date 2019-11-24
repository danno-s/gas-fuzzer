from pprint import pprint


from . import (
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanEqual,
    LessThanEqual,
    Constant,
    FunctionCall,
)

#### UTILITIES ####
def from_value(cls, value, loc, **kwargs_outer):
    def from_fuzzer(fuzzer, **kwargs_inner):
        kwargs_outer.update(kwargs_inner)
        return cls(value, fuzzer=fuzzer, loc=loc, **kwargs_outer)
    return from_fuzzer

def side(exp, parameters):
    if exp['nodeType'] == 'Identifier':
        if exp['name'] in parameters:
            side = {'name': exp['name']}
        else:
            side = None
    elif exp['nodeType'] == 'Literal':
        side = {'value': exp['value']}
    return side

def sides(function_ast, parameters):
    """
    Given an ast, parses both sides of an expression.
    Returns: 
        None, if any identifier in the expression is not in the function's signature, or if both sides are identifiers.
        The value of the literal side and a bool indicating if the value is in the left side, otherwise.
    Examples (high level):
        given:
            func a()
        then:
            sides(b != 0) => None
        
        given:
            func a(b)
        then:
            sides(b != 0) => (0, True)

        given:
            func a(b)
        then:
            sides(0 != b) => (0, False)

        given:
            func a(b, c)
        then:
            sides(b != c) => None
    """
    left = side(function_ast['leftExpression'], parameters)
    right = side(function_ast['rightExpression'], parameters)

    # First example
    if not left and not right:
        return None

    # Last example
    if ('name' in left and 'name' in right):
        return None
        
    # Second example, extract value
    if 'value' in left and right:
        return (int(left['value']), True)

    if 'value' in right and left:
        return (int(right['value']), False)

    return None

#### BINARY OPERATIONS ####
def binary_operation(function_ast, parameters, function_callback):
    if function_ast['operator'] not in binary_operators:
        raise NotImplementedError(
            f'Operator {function_ast["operator"]} not supported for BinaryOperation')

    return binary_operators[function_ast['operator']](function_ast, parameters, function_callback)

def equal(function_ast, parameters, function_callback):
    condition_sides = sides(function_ast, parameters)

    if not condition_sides:
        return None

    value, _ = condition_sides

    return from_value(Constant, { 'value': value }, function_ast['src'])

def not_equal(function_ast, parameters, function_callback):
    condition_sides = sides(function_ast, parameters)

    if not condition_sides:
        return None

    value, _ = condition_sides

    return from_value(NotEqual, { 'value': value }, loc=function_ast['src'])

def greater_than(function_ast, parameters, function_callback):
    condition_sides = sides(function_ast, parameters)

    if not condition_sides:
        return None

    value, on_left = condition_sides

    if on_left:
        # value > arg
        return from_value(LessThan, { 'max': value }, loc=function_ast['src'])
    else:
        # arg > value
        return from_value(GreaterThan, { 'min': value }, loc=function_ast['src'])

## AST to handler function binding
binary_operators = {
    '==': equal,
    '!=': not_equal,
    '>': greater_than,
}

#### UNARY OPERATIONS ####
def unary_operation(function_ast, parameters, function_callback):
    if function_ast['operator'] not in unary_operators:
        raise NotImplementedError(
            f'Operator {function_ast["operator"]} not supported for UnaryOperation')

    return unary_operators[function_ast['operator']](function_ast, parameters, function_callback)

def negate(function_ast, parameters, function_callback):
    raise NotImplementedError()

## AST to handler function binding
unary_operators = {
    '!': negate
}

#### FUNCTION CALLS ####
def function_call(function_ast, parameters, function_callback):
    if len(function_ast['expression']['argumentTypes']) > 0:
        # Not made for argument parsing yet :(
        return None

    name = function_ast['expression']['name']

    return from_value(FunctionCall, { 'name': name }, function_ast['src'], callback=function_callback)



#### ENTRY POINT ####
def new_constraint(function_ast, parameters, function_callback):
    """
    Returns a closure that initializes the given constraint,
    when fed a fuzzer instance.
    """
    if function_ast['nodeType'] not in operations:
        raise NotImplementedError(
            f'Operation type {function_ast["nodeType"]} not supported')

    return operations[function_ast['nodeType']](function_ast, parameters, function_callback)

## AST to handler function binding
operations = {
    'UnaryOperation': unary_operation,
    'BinaryOperation': binary_operation,
    'FunctionCall': function_call,
}
