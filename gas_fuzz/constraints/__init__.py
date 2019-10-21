from pprint import pprint


from .BinaryConstraints import NotEqual


def not_equal(function_ast):
    def side(exp):
        if exp['nodeType'] == 'Identifier':
            side = {'name': exp['name']}
        elif exp['nodeType'] == 'Literal':
            side = {'value': exp['value']}
        return side

    left_ex = function_ast['leftExpression']
    left_side = side(left_ex)

    right_ex = function_ast['rightExpression']
    right_side = side(right_ex)

    return NotEqual(left_side, right_side)


binary_operators = {
    '!=': not_equal
}


def binary_operation(function_ast):
    if function_ast['operator'] not in binary_operators:
        raise NotImplementedError(
            f'Operator {function_ast["operator"]} not supported for BinaryOperation')

    return binary_operators[function_ast['operator']](function_ast)


def negate(function_ast):
    raise NotImplementedError()


unary_operators = {
    '!': negate
}


def unary_operation(function_ast):
    if function_ast['operator'] not in unary_operators:
        raise NotImplementedError(
            f'Operator {function_ast["operator"]} not supported for UnaryOperation')

    return unary_operators[function_ast['operator']](function_ast)


operations = {
    'UnaryOperation': unary_operation,
    'BinaryOperation': binary_operation
}


def new_constraint(function_ast):
    print('============= CONSTRAINT FOUND ================')
    if function_ast['nodeType'] not in operations:
        raise NotImplementedError(
            f'Operation type {function_ast["nodeType"]} not supported')

    return operations[function_ast['nodeType']](function_ast)
