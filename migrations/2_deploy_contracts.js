var OrderBook = artifacts.require("OrderBook");module.exports = function(deployer) {
    deployer.deploy(OrderBook);
  };