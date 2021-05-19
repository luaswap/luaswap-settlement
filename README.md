# LuaSwap Settlement

This repository contains solidity contracts to enable **limit orders** for LuaSwap.

## Overview

Typically AMMs only settle orders with market price, which represents a significant limitation compared to orderbook driven exchanges. LuaSwap addresses this critical AMM pain point with the release of the limit order feature.

Contracts in this repo help you submit a limit order with a lower price than what it is now. Later, when the price gets lower enough to meet the requirement of your order, it gets settled.


## Contracts
Limit orders on LuaSwap work in a completely decentralized manner, without the need of any centralized authority. The system consists of two contracts: OrderBook and Settlement.

### OrderBook
`OrderBook` is deployed at `0x9701554EBD790EAF258d5A2131f00ac72525DE42`.

`OrderBook` keeps limit orders that users have submitted. Anyone can call `createOrder()` to create a limit order with the amount to sell and the minimum price. He/she needs to approve the amount to sell for the `Settlement` contract.

### Settlement
`Settlement` is deployed at `0x3fcF522bAA0Ab1D9a1f77EFaC7DC1aC0C5dEBC63`.

`Settlement` is in charge of swapping tokens for orders. Anyone can call `fillOrder()` to fill the order submitted. We'll call this caller a 'relayer'. Relayers need to call it with proper parameters to meet the minimum price requirement set in the order. If the call is successful, fee will be transferred to the relayer.

The maker of an order can cancel it with `cancelOrder()` on `Settlement`.

It is possible to fill only a certain amount of tokens, not all. In most cases, submitted orders will reside on the `OrderBook` and their amount will be filled by different callers in different blocks.

## Incentives
### Relayer
`Settlement` is a wrapper contract around `UniswapV2Router02`. Every function in this contract has a duplicated version in the `Settlement` with an extra parameter `args`. If `args` is not empty, it is used for filling orders; see `Settlement.fillOrders()` for details.
 
### Fee
For every `fillOrder()` call, 0.4% swap fee of the amount sold is charged.


## Audits


## License
MIT
