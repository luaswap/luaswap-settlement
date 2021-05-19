const HDWalletProvider = require("@truffle/hdwallet-provider");
const mnemonic = "casino divert first man badge kid garden type ignore angry awkward word";

module.exports = {
  networks: {
    tomotest: {
      provider: () => new HDWalletProvider(
        mnemonic,
        "https://rpc.testnet.tomochain.com",
        0,
        1,
        true,
        "m/44'/889'/0'/0/",
      ),
      network_id: "89",
      gas: 5000000,
      gasPrice: 10000000000000,
    }
  },
  compilers: {
    solc: {
      version: "0.6.12"  // ex:  "0.4.20". (Default: Truffle's installed solc)
    }
 }
};