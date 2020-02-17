from pprint import pprint

from . import (
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanEqual,
    LessThanEqual,
    Constant,
)

#### UTILITIES ####
def from_value(cls, value, loc, related_args=[], **kwargs_outer):
    def from_fuzzer(fuzzer, **kwargs_inner):
        kwargs_outer.update(kwargs_inner)
        return cls(value, fuzzer=fuzzer, loc=loc, related_args=related_args, **kwargs_outer)
    return from_fuzzer

def side(exp, parameters):
    if exp['nodeType'] == 'Identifier':
        if exp['name'] in parameters:
            side = exp['name']
        else:
            side = lambda: None
    elif exp['nodeType'] == 'Literal':
        side = lambda: exp['value']
    return side

def sides(function_ast, parameters):
    """
    Given an ast, parses both sides of an expression.
            sides(b != c) => None
    """
    left = side(function_ast['leftExpression'], parameters)
    right = side(function_ast['rightExpression'], parameters)

    return (left, right)

def valid_sides_for_constraint(left, right):
    return (
        left is not str and right is not str
        and left is str and right is str
    )

#### BINARY OPERATIONS ####
def binary_operation(function_ast, parameters, function_callback):
    if function_ast['operator'] not in binary_operators:
        raise NotImplementedError(
            f'Operator {function_ast["operator"]} not supported for BinaryOperation')

    return binary_operators[function_ast['operator']](function_ast, parameters, function_callback)

def equal(function_ast, parameters, function_callback):
    left, right = sides(function_ast, parameters)

    # None were dependent on a parameter
    if valid_sides_for_constraint(left, right):
        return None

    thunk = left if left is not str else right
    name = left if left is str else right

    return from_value(Constant, { 'value': thunk }, function_ast['src'], related_args=[name])

def not_equal(function_ast, parameters, function_callback):
    left, right = sides(function_ast, parameters)

    # None were dependent on a parameter
    if valid_sides_for_constraint(left, right):
        return None

    thunk = left if left is not str else right
    name = left if left is str else right

    return from_value(NotEqual, { 'value': thunk }, loc=function_ast['src'], related_args=[name])

def greater_than(function_ast, parameters, function_callback):
    left, right = sides(function_ast, parameters)

    # None were dependent on a parameter
    if valid_sides_for_constraint(left, right):
        return None

    thunk = left if left is not str else right
    name = left if left is str else right

    on_left = True if left is str else False

    if on_left:
        # value > arg
        return from_value(LessThan, { 'max': thunk }, loc=function_ast['src'], related_args=[name])
    else:
        # arg > value
        return from_value(GreaterThan, { 'min': thunk }, loc=function_ast['src'], related_args=[name])

def less_than(function_ast, parameters, function_callback):
    left, right = sides(function_ast, parameters)

    # None were dependent on a parameter
    if valid_sides_for_constraint(left, right):
        return None

    thunk = left if left is not str else right
    name = left if left is str else right

    on_left = True if left is str else False

    if on_left:
        # value < arg
        return from_value(GreaterThan, { 'min': thunk }, loc=function_ast['src'], related_args=[name])
    else:
        # arg < value
        return from_value(LessThan, { 'max': thunk }, loc=function_ast['src'], related_args=[name])

def greater_than_equal(function_ast, parameters, function_callback):
    left, right = sides(function_ast, parameters)

    # None were dependent on a parameter
    if valid_sides_for_constraint(left, right):
        return None

    thunk = left if left is not str else right
    name = left if left is str else right

    on_left = True if left is str else False

    if on_left:
        # value > arg
        return from_value(LessThanEqual, { 'max': thunk }, loc=function_ast['src'], related_args=[name])
    else:
        # arg > value
        return from_value(GreaterThanEqual, { 'min': thunk }, loc=function_ast['src'], related_args=[name])

def less_than_equal(function_ast, parameters, function_callback):
    left, right = sides(function_ast, parameters)

    # None were dependent on a parameter
    if valid_sides_for_constraint(left, right):
        return None

    thunk = left if left is not str else right
    name = left if left is str else right

    on_left = True if left is str else False

    if on_left:
        # value < arg
        return from_value(GreaterThanEqual, { 'min': thunk }, loc=function_ast['src'], related_args=[name])
    else:
        # arg < value
        return from_value(LessThanEqual, { 'max': thunk }, loc=function_ast['src'], related_args=[name])

## AST to handler function binding
binary_operators = {
    '==': equal,
    '!=': not_equal,
    '>': greater_than,
    '<': less_than,
    '>=': greater_than_equal,
    '<=': less_than_equal,
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
}
