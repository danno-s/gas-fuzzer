import sys
import os
import matplotlib.pyplot as plt
import seaborn as sn
import pandas as pd

if len(sys.argv) < 2:
    print("Call script with root folder of the results")
    sys.exit(1)

def get_range(expected_cost, costs):
        min_cost = min(costs)
        max_cost = max(costs)
        if expected_cost != 'infinite':
            exp_cost = int(expected_cost)
            if exp_cost < min_cost:
                return (exp_cost, max_cost + 10)
            elif exp_cost > max_cost:
                return (min_cost - 10, exp_cost)
        return (min_cost - 10, max_cost + 10)

def graph(result_path, expected_cost, actual_costs):
    leg = []
    if expected_cost != "infinite":
        plt.axvline(
            x=int(expected_cost),
            color=(1, 100/255, 100/255, 0.8),
            linestyle='--',
            zorder=-1
        )
        leg.append("Expected cost")
    plt.hist(x=actual_costs, range=get_range(expected_cost, actual_costs), color=(100/255, 100/255, 1, 0.8))
    plt.xlabel("Gas cost")
    plt.ylabel("Frequency")
    plt.title(f"Gas costs of {contract}.{function}")

    plt.axvline(
        x=sum(actual_costs) / len(actual_costs),
        color=(150/255, 1, 150/255, 0.8),
        linestyle='-',
        zorder=-1
    )
    leg.append("Average cost")
    plt.legend(leg)

    exp, cost = classify(expected_cost, actual_costs)

    plt.figtext(0.5, 0.05, f"Classified as ({exp}, {cost})", wrap = True, horizontalalignment="center", weight='ultralight')

    plt.gcf().subplots_adjust(bottom=0.2)

    result_dir = os.path.dirname(result_path)
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)

    plt.savefig(result_path)
    plt.close()


def frequencies(costs):
    return {
        cost: costs.count(cost) for cost in set(costs)
    }

def decreasing(frequencies):
    prev_freq = max(frequencies.values())
    for cost in sorted(frequencies.keys()):
        if frequencies[cost] > prev_freq:
            return False
        prev_freq = frequencies[cost]
    return True

def increasing(frequencies):
    prev_freq = 0
    for cost in sorted(frequencies.keys()):
        if frequencies[cost] < prev_freq:
            return False
        prev_freq = frequencies[cost]
    return True

def classify(expected_cost, actual_costs):
    avg = sum(actual_costs) / len(actual_costs)
    if expected_cost == "infinite":
        exp_class = "none"
    elif int(expected_cost) < avg:
        exp_class = "less_than"
    elif int(expected_cost) > avg:
        exp_class = "greater_than"
    else:
        exp_class = "equal"

    freq = frequencies(actual_costs)

    if len(freq.keys()) == 1:
        cost_class = "constant"
    elif decreasing(freq):
        cost_class = "decreasing"
    elif increasing(freq):
        cost_class = "increasing"
    else:
        cost_class = "other"
    
    return exp_class, cost_class

def plot_classifications(classifications):
    array = [
        [
            count for count in cost_classifiations.values()
        ] for cost_classifiations in classifications.values()
    ]

    exps = list(classifications.keys())
    costs = list(classifications['none'].keys())

    df = pd.DataFrame(array, exps, costs)
    plt.figure(figsize=(10,7))
    sn.set(font_scale=1.4)
    sn.heatmap(df, annot=True, annot_kws={"size": 16})
    plt.title("Classification heatmap")
    plt.gcf().subplots_adjust(left=0.2)
    plt.savefig("heatmap.png")
    plt.close()


if __name__ == "__main__":
    results_root = sys.argv[1]

    expected_cost_classifications = [
        'less_than',
        'greater_than',
        'none',
        'equal'
    ]

    actual_cost_classifications = [
        'constant',
        'decreasing',
        'increasing',
        "other"
    ]

    classifications = {
        exp_class: {
            cost_class: 0 for cost_class in actual_cost_classifications
        } for exp_class in expected_cost_classifications
    }

    for root, dirs, results in os.walk(results_root):
        for result in results:
            relative_path = f"{root}/{result}"
            _, file, contract, function = relative_path.split(os.sep)
            save_path = f"processed_results/{file}/{contract}/{function}.png"
            with open(relative_path) as func_results:
                expected_cost = func_results.readline()
                actual_costs = [int(actual_cost) for actual_cost in func_results]

            graph(save_path, expected_cost, actual_costs)            

            exp, cost = classify(expected_cost, actual_costs)
            classifications[exp][cost] += 1

    plot_classifications(classifications)