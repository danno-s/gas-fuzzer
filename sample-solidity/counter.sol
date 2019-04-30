pragma solidity ^0.4.11;

contract Counter {
    uint private count;

    constructor() public {
        count = 1;
    }
    
    function add() public {
        count += count;
    }

    function read() public view returns(uint) {
        return count;
    }
}