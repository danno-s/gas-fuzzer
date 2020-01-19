from .base import BaseTypeFuzzer

class NumericTypeFuzzer(BaseTypeFuzzer):
    def __init__(self, min=None, max=None, **kwargs):
        self.min = min
        self.max = max
        super().__init__(**kwargs)

    def greater_than(self, value):
        '''Set this fuzzer to generate values greater than to value
        '''
        self.greater_than_equal(value + 1)
    
    def less_than(self, value):
        '''Set this fuzzer to generate values less than to value
        '''
        self.less_than_equal(value - 1)

    def greater_than_equal(self, value):
        '''Set this fuzzer to generate values greater than or equal to value
        '''
        if self.min < value:
            self.min = value
    
    def less_than_equal(self, value):
        '''Set this fuzzer to generate values less than or equal to value
        '''
        if self.max > value:
            self.max = value

    def empty_set(self):
        if super().empty_set():
            return True

        # lower and upper bounds passed each other
        if self.max < self.min:
            return True

    def constraints_to_str(self):
        return f"""{self.pretty_str()}:
        Minimum value: {self.min}
        Maximum value: {self.max}
        """ + str(super())
