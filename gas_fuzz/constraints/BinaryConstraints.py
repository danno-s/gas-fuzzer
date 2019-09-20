class NotEqual:
    def __init__(self, left_side, right_side):
        self.left_side = left_side
        self.right_side = right_side

    def __repr__(self):
        def side_to_str(side):
            return side['name'] if 'name' in side else side['value']

        return f'{side_to_str(self.left_side)} != {side_to_str(self.right_side)}'

    def passable(self, contract_variables, function_parameters):
        return False

    def passes(self, contract_variables, function_parameters, arguments):
        return False
