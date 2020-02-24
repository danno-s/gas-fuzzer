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

def side(exp, parameters, function_callback):
    if exp['nodeType'] == 'Identifier':
        if exp['name'] in parameters:
            side = None, exp['name']
        else:
            side = lambda: function_callback(exp['name']), exp['name']
    elif exp['nodeType'] == 'Literal':
        side = lambda: exp['value'], None
    return side

def sides(function_ast, parameters, function_callback):
    """
    Given an ast, parses both sides of an expression.
            sides(b != c) => None
    """
    left = side(function_ast['leftExpression'], parameters, function_callback)
    right = side(function_ast['rightExpression'], parameters, function_callback)

    return (left, right)

#### BINARY OPERATIONS ####
def binary_operation(function_ast, parameters, function_callback):
    if function_ast['operator'] not in binary_operators:
        raise NotImplementedError(
            f'Operator {function_ast["operator"]} not supported for BinaryOperation')

    return binary_operators[function_ast['operator']](function_ast, parameters, function_callback)

def equal(function_ast, parameters, function_callback):
    leftTuple, rightTuple = sides(function_ast, parameters, function_callback)
    left, leftName = leftTuple
    right, rightName = rightTuple

    thunk = left if left is not None else right

    return from_value(Constant, { 'value': thunk }, function_ast['src'], related_args=[leftName, rightName])

def not_equal(function_ast, parameters, function_callback):
    leftTuple, rightTuple = sides(function_ast, parameters, function_callback)
    left, leftName = leftTuple
    right, rightName = rightTuple

    thunk = left if left is not None else right

    return from_value(NotEqual, { 'value': thunk }, loc=function_ast['src'], related_args=[leftName, rightName])

def greater_than(function_ast, parameters, function_callback):
    leftTuple, rightTuple = sides(function_ast, parameters, function_callback)
    left, leftName = leftTuple
    right, rightName = rightTuple

    thunk = left if left is not None else right

    on_left = True if left is not None else False

    if on_left:
        # value > arg
        return from_value(LessThan, { 'max': thunk }, loc=function_ast['src'], related_args=[leftName, rightName])
    else:
        # arg > value
        return from_value(GreaterThan, { 'min': thunk }, loc=function_ast['src'], related_args=[leftName, rightName])

def less_than(function_ast, parameters, function_callback):
    leftTuple, rightTuple = sides(function_ast, parameters, function_callback)
    left, leftName = leftTuple
    right, rightName = rightTuple

    thunk = left if left is not None else right

    on_left = True if left is not None else False

    if on_left:
        # value < arg
        return from_value(GreaterThan, { 'min': thunk }, loc=function_ast['src'], related_args=[leftName, rightName])
    else:
        # arg < value
        return from_value(LessThan, { 'max': thunk }, loc=function_ast['src'], related_args=[leftName, rightName])

def greater_than_equal(function_ast, parameters, function_callback):
    leftTuple, rightTuple = sides(function_ast, parameters, function_callback)
    left, leftName = leftTuple
    right, rightName = rightTuple

    thunk = left if left is not None else right

    on_left = True if left is not None else False

    if on_left:
        # value > arg
        return from_value(LessThanEqual, { 'max': thunk }, loc=function_ast['src'], related_args=[leftName, rightName])
    else:
        # arg > value
        return from_value(GreaterThanEqual, { 'min': thunk }, loc=function_ast['src'], related_args=[leftName, rightName])

def less_than_equal(function_ast, parameters, function_callback):
    leftTuple, rightTuple = sides(function_ast, parameters, function_callback)
    left, leftName = leftTuple
    right, rightName = rightTuple

    thunk = left if left is not None else right

    on_left = True if left is not None else False

    if on_left:
        # value < arg
        return from_value(GreaterThanEqual, { 'min': thunk }, loc=function_ast['src'], related_args=[leftName, rightName])
    else:
        # arg < value
        return from_value(LessThanEqual, { 'max': thunk }, loc=function_ast['src'], related_args=[leftName, rightName])

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

    function_callback is a function that takes a single argument,
    the name of a state variable, and returns its value
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
