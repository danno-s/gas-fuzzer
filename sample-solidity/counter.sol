pragma solidity ^0.4.11;

contract Counter {
    uint public count;

    constructor() public {
        count = 1;
    }

    function divide(uint8 factor) public returns (uint) {
        count /= factor;
        return count;
    }

    function add(uint8 value) public returns (uint) {
        count += value;
        return count;
    }
}