// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

import "../libraries/Orders.sol";

interface IOrderBook {
    function createOrder(Orders.Order memory order) external;
    function orderOfHash(bytes32 hash) external returns (Orders.Order memory);
}
