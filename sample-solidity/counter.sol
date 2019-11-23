pragma solidity ^0.4.11;

contract Counter {
    uint public count;

    constructor() public {
        count = 1;
    }

    function divide(uint8 factor) public returns (uint) {
        require(factor != 0, "Can't divide by 0");

        if (factor > 0) {
            require(factor > 1, "Must divide by greater than 1");
            count /= -factor;
        }
        count /= factor;
        return count;
    }

    function add(uint8 value) public returns (uint) {
        require(always_true(), "How did this happen?");

        count += value;
        return count;
    }

    function always_true() public returns (bool) {
        return true;
    }
}
