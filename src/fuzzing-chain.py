from eth.chains.base import MiningChain
from eth.db.atomic import AtomicDB

class FuzzingChain(MiningChain):
    def __init__(self, contracts, header=None):
        if header is None:
            header = {}
        
        # Set minimum difficulty for fast emulation
        header['difficulty'] = 1

        return super().__init__(AtomicDB, header=header)

    def fuzz(log = None):
        pass