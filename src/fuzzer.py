SOLIDITY_TYPE_GRAMMAR = {
    '<address>': [
        '0x<hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte><hexbyte>'
    ],
    '<bool>': [
        'true',
        'false'
    ],
    '<string>': [
        '<single-quote><string-content><single-quote>',
        '<double-quote><string-content><double-quote>',
        '<single-quote><string-content><double-quote><string-content><double-quote><string-content><single-quote>',
        '<double-quote><string-content><single-quote><string-content><single-quote><string-content><double-quote>'
    ],
    '<string-content>': [
        '<symbol>',
        '<symbol><string-content>'
    ],
    '<symbol>': [

    ],
    '<hexbyte>': [
        '<hex><hex>'
    ],
    '<hex>': [
        '<digit>', 'a', 'b', 'c', 'd', 'e', 'f'
    ],
    '<digit>': [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    ]
}

class SolidityFuzzer():
    def __init__(self, seed):
        self.seed = seed

    def generate_args(self, args):
        return b''.join(self.fuzz_arg(arg) for arg in args)

    def fuzz_arg(self, arg):
        pass