import matplotlib.pyplot as plt
import os

class FuzzingData:
    def __init__(self):
        self.expected_costs = {}
        self.actual_costs = {}

    def merge(self, data):
        # Overwrite because they should be deterministic between the same inputs
        self.expected_costs = data.expected_costs

        for contract_name in data.actual_costs.keys():
            if contract_name not in self.actual_costs:
                self.actual_costs[contract_name] = {}
            for function_name in data.actual_costs[contract_name].keys():
                if function_name in self.actual_costs[contract_name]:
                    self.actual_costs[contract_name][function_name] += data.actual_costs[contract_name][function_name]
                else:
                    self.actual_costs[contract_name][function_name] = data.actual_costs[contract_name][function_name]

    def set_expected_cost(self, contract, fun, expected_cost):
        if contract not in self.expected_costs:
            self.expected_costs[contract] = {}
        self.expected_costs[contract][fun] = expected_cost

    def register_call(self, contract, fun, gas_cost):
        if contract not in self.actual_costs:
            self.actual_costs[contract] = {}
        if fun not in self.actual_costs[contract]:
            self.actual_costs[contract][fun] = []
        self.actual_costs[contract][fun].append(gas_cost)

    def export(self, folder="", filename="result"):
        for contract in self.actual_costs.keys():
            for function in self.actual_costs[contract].keys():
                path = f"{folder}/{filename}/{contract}"
                if not os.path.exists(path):
                    os.makedirs(path)
                with open(path + f"/{function}", "w") as file:
                    lines = f"{self.expected_costs[contract][function]}\n"
                    for cost in self.actual_costs[contract][function]:
                        lines += f"{cost}\n"

                    file.writelines(lines)
