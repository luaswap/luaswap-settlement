pragma solidity >=0.5.0;

interface IUniswapV2Factory {
    event PairCreated(address indexed token0, address indexed token1, address pair, uint);

    function feeTo() external view returns (address);
    function withdrawFeeTo() external view returns (address);
    function swapFee() external view returns (uint);
    function withdrawFee() external view returns (uint);
    
    function feeSetter() external view returns (address);
    function migrator() external view returns (address);

    function isTRC21(address token) external view returns (bool);
    function getPair(address tokenA, address tokenB) external view returns (address pair);
    function allPairs(uint) external view returns (address pair);
    function allPairsLength() external view returns (uint);
    function getTransferFee(address token, uint256 amount) external view returns (uint256);

    function createPair(address tokenA, address tokenB) external returns (address pair);
    function createPairTRC21(address tokenA, address tokenB, bool AIsTRC21, bool BIsTRC21) external returns (address pair);
    function setIsTRC21(address token) external;

    function setFeeTo(address) external;
    function setWithdrawFeeTo(address) external;
    function setSwapFee(uint) external;
    function setFeeSetter(address) external;
    function setMigrator(address) external;
}
