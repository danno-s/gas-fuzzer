from .base import BaseTypeFuzzer
import logging

class NumericTypeFuzzer(BaseTypeFuzzer):
    def __init__(self, min=None, max=None, **kwargs):
        self.base_min = min
        self.base_max = max
        self.min = min if callable(min) else lambda: min
        self.max = max if callable(max) else lambda: max
        super().__init__(**kwargs)

    def greater_than(self, valueThunk):
        '''Set this fuzzer to generate values greater than to value
        '''
        self.greater_than_equal(lambda: valueThunk() + 1)
    
    def less_than(self, valueThunk):
        '''Set this fuzzer to generate values less than to value
        '''
        self.less_than_equal(lambda: valueThunk() - 1)

    def greater_than_equal(self, valueThunk):
        '''Set this fuzzer to generate values greater than or equal to value
        '''
        if self.min is not None and self.min() < float(valueThunk()) and self.base_min > float(valueThunk()):
            if (type(valueThunk()) is str):
                self.min = lambda: float(valueThunk())
            else:
                self.min = valueThunk
    
    def less_than_equal(self, valueThunk):
        '''Set this fuzzer to generate values less than or equal to value
        '''
        if self.max is not None and self.max() > float(valueThunk()) and self.base_max < float(valueThunk()):
            if (type(valueThunk()) is str):
                self.max = lambda: float(valueThunk())
            else:
                self.max = valueThunk

    def empty_set(self):
        if super().empty_set():
            return True

        # lower and upper bounds passed each other
        if self.max() < self.min():
            return True

    def constraints_to_str(self):
        return f"""{self.pretty_str()}:
        Minimum value: {self.min()}
        Maximum value: {self.max()}
        """ + str(super())
