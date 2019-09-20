from threading import Lock

class ProgressBar():
    def __init__(self, total_ops, preamble=None):
        self.current_ops = 0
        self.total_ops = total_ops
        self.preamble = preamble
        self.lock = Lock()
        self.render()

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, type, value, traceback):
        self.lock.release()

    def render(self):
        print(f"{self.preamble if self.preamble else ''} {self.current_ops * 100 / self.total_ops:.2f}%", end="\r", flush=True)

    def update(self):
        self.current_ops += 1
        self.render()
