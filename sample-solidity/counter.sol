pragma solidity ^0.4.11;

contract Counter {
    uint private hidden;
    uint public count;
    uint private hidden2;

    constructor() public {
        count = 1;
    }

    function divide(uint8 factor, uint8 not_used) public returns (uint) {
        require(factor >= 0, "Can't divide by 0");

        require(factor <= 15, "Arbitrary rule!");

        if (factor > 0) {
            count /= -factor;
        }
        count /= factor;
        return count;
    }

    function add(uint8 value) public returns (uint) {
        // require(always_false(), "How did this happen?");

        count += value;
        return count;
    }

    function always_false() public pure returns (bool) {
        return false;
    }
}
