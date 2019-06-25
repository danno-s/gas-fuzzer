import matplotlib.pyplot as plt
import os

class FuzzingData:
    def __init__(self):
        self.expected_costs = {}
        self.functions = {}

    def merge(self, data):
        self.expected_costs = data.expected_costs

        for key in data.functions.keys():
            if key in self.functions:
                self.functions[key] += data.functions[key]
            else:
                self.functions[key] = data.functions[key]

    def set_expected_cost(self, fun, expected_cost):
        self.expected_costs[fun] = expected_cost

    def register_call(self, fun, gas_cost):
        if fun not in self.functions:
            self.functions[fun] = []
        self.functions[fun].append(gas_cost)

    def export(self, folder="", filename="result"):
        for fun in self.functions.keys():
            dir = f"{folder}/{filename}/"
            if not os.path.exists(dir):
                os.makedirs(dir)
            plt.hist(self.functions[fun])
            plt.xlabel("Gas cost")
            plt.ylabel("Frequency")
            plt.title(f"Gas costs of {fun} {('[Expected: ' + self.expected_costs[fun] + ']') if fun in self.expected_costs else ''}")
            plt.savefig(f"{dir}{fun.replace(' ', '-')}.png")
            plt.close()
