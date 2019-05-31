import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

class FuzzingData:
    def __init__(self):
        self.expected_costs = {}
        self.functions = {}

    def set_expected_cost(self, fun, expected_cost):
        self.expected_costs[fun] = expected_cost

    def register_call(self, fun, gas_cost):
        if fun not in self.functions:
            self.functions[fun] = []
        self.functions[fun].append(gas_cost)

    def export(self):
        with PdfPages("report.pdf") as export_pdf:
            for fun in self.functions.keys():
                plt.hist(self.functions[fun])
                plt.xlabel("Gas cost")
                plt.ylabel("Frequency")
                plt.title(f"Gas costs of {fun} {('[Expected: ' + self.expected_costs[fun] + ']') if fun in self.expected_costs else ''}")
                export_pdf.savefig()
                plt.close()
