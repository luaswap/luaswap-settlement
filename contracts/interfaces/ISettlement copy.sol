// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

interface ISettlement {
    event OrderFilled(bytes32 indexed hash, uint256 amountIn, uint256 amountOut);
    event OrderCanceled(bytes32 indexed hash);
    event FeeTransferred(bytes32 indexed hash, address indexed recipient, uint256 amount);
    event FeeSplitTransferred(bytes32 indexed hash, address indexed recipient, uint256 amount);

    struct Order {
        bytes32 hash;
        address maker;
        address fromToken;
        address toToken;
        uint256 amountIn;
        uint256 amountOutMin;
        address recipient;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 amountToFillIn;
        address[] path;
    }

    function fillOrder(Order calldata args) external returns (uint256 amountOut);

    function cancelOrder(bytes32 hash) external;
    function swapExactTokensForTokens(address from,
                        uint256 amountIn,
                        uint256 amountOutMin,
                        address[] memory path,
                        address to) external;
}
