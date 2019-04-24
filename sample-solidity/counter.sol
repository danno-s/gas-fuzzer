pragma solidity ^0.4.11;

contract Counter {
    uint private count;

    constructor() public {
        count = 1;
    }
    
    function add() public {
        for (uint i = 0; i < count; i++) {
            count++;
        }
    }

    function read(uint unused1, uint unused2) public view returns(uint) {
        return count + unused1 - unused2;
    }
}