pragma solidity ^0.4.11;

contract Counter {
    uint public count;

    function Counter() {
        count = 1;
    }
    
    function add() {
        for (uint i = 0; i < count; i++) {
            count++;
        }
    }
}