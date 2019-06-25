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
            leg = []
            if fun in self.expected_costs and self.expected_costs[fun] != 'infinite':
                plt.axvline(
                    x=int(self.expected_costs[fun]),
                    color=(1, 100/255, 100/255, 0.8),
                    linestyle='--',
                    zorder=-1
                )
                leg.append("Expected cost")
            plt.hist(x=self.functions[fun], range=self.get_range(fun), color=(100/255, 100/255, 1, 0.8))
            plt.xlabel("Gas cost")
            plt.ylabel("Frequency")
            plt.title(f"Gas costs of {fun} {('[Expected: ' + self.expected_costs[fun] + ']') if fun in self.expected_costs else ''}")

            plt.axvline(
                x=self.get_average(fun),
                color=(150/255, 1, 150/255, 0.8),
                linestyle='-',
                zorder=-1
            )
            leg.append("Average cost")
            plt.legend(leg)

            plt.savefig(f"{dir}{fun.replace(' ', '-')}.png")
            plt.close()

    def get_average(self, fun):
        s = 0
        for v in self.functions[fun]:
            s += v
        return s / len(self.functions[fun])

    def get_range(self, fun):
        min_cost = min(self.functions[fun])
        max_cost = max(self.functions[fun])
        if fun in self.expected_costs and self.expected_costs[fun] != 'infinite':
            exp_cost = int(self.expected_costs[fun])
            if exp_cost < min_cost:
                return (exp_cost, max_cost + 10)
            elif exp_cost > max_cost:
                return (min_cost - 10, exp_cost)
        return (min_cost - 10, max_cost + 10)
