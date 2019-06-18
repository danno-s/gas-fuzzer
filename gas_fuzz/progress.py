from threading import Lock

class ProgressBar():
    def __init__(self, total_ops):
        self.current_ops = 0
        self.total_ops = total_ops
        self.lock = Lock()
        self.render()

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, type, value, traceback):
        self.lock.release()

    def render(self):
        print("{0:.2f}%".format(self.current_ops * 100 / self.total_ops), end="\r", flush=True)

    def update(self):
        self.current_ops += 1
        self.render()
