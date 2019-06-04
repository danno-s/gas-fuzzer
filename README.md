<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
  * [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Usage](#usage)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgements](#acknowledgements)



<!-- ABOUT THE PROJECT -->
## About The Project
This fuzzer was made to learn empirically the gas expenses of your contracts. It is highly configurable through a `rules.json` file, and doesn't require you to modify your source code to obtain useful information about its execution.

### Built With
* [PyEVM](https://github.com/ethereum/py-evm)

<!-- GETTING STARTED -->
## Getting Started

Testing was done in a clean virtual environment, so I recommend doing so to run this fuzzer.

### Prerequisites

You must have a working python3 installation, and pip installed.

### Installation

Inside your virtual environment, run:
```
pip install -U -r requirements.txt
```

<!-- USAGE EXAMPLES -->
## Usage

You can execute the fuzzer like so:
```
python3 gas_fuzz [OPTIONS] files [files...]
```

The default behaviour is to run 10 transactions each block, during 10 blocks, and record the behaviour of the gas costs of each function call.

### Command Line Arguments

All options and their arguments can be described by executing
```
python3 gas_fuzz --help
```

The options you'll probably use the most are:
- `n [number]`: Optional. Defines the number of blocks to mine during the fuzzing.
- `tx [number]`: Optional. Defines the number of transactions to include per block.
- `r [file]`: Optional. Specifies the rule file to use for fuzzing.

### Rules

You can define how the fuzzer should generate its arguments by using a JSON file. A prototype of the expected JSON files can be found in `prototype.json`

<!-- LICENSE
## License

Distributed under the MIT License. See `LICENSE` for more information.
-->


<!-- CONTACT -->
## Contact

Daniel Soto - [@dannoo_s](https://twitter.com/dannoo_s) - danielsoto.3004@gmail.com

Project Link: [https://github.com/danno-s/gas-fuzzer](https://github.com/danno-s/gas-fuzzer)
