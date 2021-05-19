const HDWalletProvider = require("@truffle/hdwallet-provider");
const mnemonic = "capable bleak north praise fog almost struggle legal stand apology select crouch";
module.exports = {
    defaultNetwork: 'hardhat',
    networks: {
      hardhat: {},
      dev: {
        accounts: {
            mnemonic: mnemonic,
            path: "m/44'/889'/0'/0/",
            initialIndex: 0,
            count: 1,
        },
          url: "https://rpc.testnet.tomochain.com",
          network_id: "89",
          gas: 2000000,
          gasPrice: 10000000000000,
      },
      quorum: {
        url: 'http://127.0.0.1:22000',
      },
    },
    solidity: {
      version: '0.6.12',
      settings: {
        optimizer: {
          enabled: true,
          runs: 200,
        },
      },
    },
    paths: {
      sources: './contracts',
      tests: './test',
      cache: './cache',
      artifacts: './artifacts',
    },
    mocha: {
      timeout: 20000,
    },
  };