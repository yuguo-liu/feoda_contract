// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Wesolowski-VDF/WesolowskiVDFVerifier.sol";
import "./AES/aes128-gcm.sol";

contract Feoda {
    // definition of tre
    struct Tre {
        bytes c;
        bytes x;
        bytes y;
        bytes N;
        bytes proof;
        uint256 security_param;
        uint delay;
    }

    address public alice;
    address public bob;
    uint256 public amount;  // amount a
    uint256 public deposit; // deposit 0.01a
    uint256 public totalAmount; // total amount 1.01a
    uint256 public exchangeRate; // exchange rate: required to get by Chainlink
    
    bytes public bankReceiptEnc;    // the bank receipt (enc)
    bytes public bankReceiptDec;    // the bank receipt
    bool public isDepositToContract; // whether alice deposit the ETH to the contract
    bool public isUploadBankReceipt;

    Tre public tre;

    // 事件声明
    event Deposit(address indexed user, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event EncryptedDataUploaded(bytes encryptedData);
    event BankReceiptUploaded(bytes bankReceipt);
    event TransferCompleted(address indexed to, uint256 amount);

    // 合约构造函数
    constructor(address _bob, uint256 _amount, uint256 _exchangeRate) {
        alice = msg.sender;  // Alice的地址
        bob = _bob;          // Bob的地址
        amount = _amount;
        deposit = amount / 100;  // 押金0.01a
        totalAmount = amount + deposit;  // 总金额1.01a
        exchangeRate = _exchangeRate;
        isDepositToContract = false;
        isUploadBankReceipt = false;
    }

    // Alice向合约存入ETH
    function depositToContract() external payable {
        require(msg.sender == alice, "Only Alice can deposit.");
        require(msg.value == totalAmount, "Deposit amount must be more than 1.01a.");
        emit Deposit(msg.sender, msg.value);
        isDepositToContract = true;
    }

    // 查询交易信息
    function getTransactionInfo() external view returns (address, address, uint256, uint256, uint256, uint256, bool) {
        return (alice, bob, amount, deposit, totalAmount, exchangeRate, isDepositToContract);
    }

    // Alice主动发起转账
    function transferToBob() external {
        require(msg.sender == alice, "Only Alice can initiate transfer.");
        require(address(this).balance >= totalAmount, "Insufficient balance.");
        payable(bob).transfer(amount);  // Bob提取本金
        payable(alice).transfer(deposit);  // Alice提取押金
        emit Transfer(msg.sender, bob, amount);
        emit Transfer(msg.sender, alice, deposit);
        isDepositToContract = false;
    }

    // Alice上传time release encryption密文
    function uploadEncryptedData(
        bytes memory _c,
        bytes memory _x,
        bytes memory _N,
        uint256 security_param,
        uint _delay
    ) external {
        require(msg.sender == alice, "Only Alice can upload encrypted data.");
        tre.c = _c;
        tre.x = _x;
        tre.N = _N;
        tre.delay = _delay;
        tre.security_param = security_param;
        emit EncryptedDataUploaded(_c);
    }

    // Bob upload the receipt (encrypted) and get the TRE
    function uploadBankReceipt(
        bytes memory _bankReceipt
    ) external {
        require(msg.sender == bob, "Only Bob can upload bank receipt.");
        bankReceiptEnc = _bankReceipt;
        emit BankReceiptUploaded(_bankReceipt);
        isUploadBankReceipt = true;
    }

    function getTimeReleasedCipher() external view returns (
        uint256, uint256, bytes memory, bytes memory, bytes memory
    ) {
        require(isUploadBankReceipt, "plz upload bank receipt first");
        return (tre.delay, tre.security_param, tre.N, tre.x, tre.c);
    }

    // Bob提交time release encryption明文及证明
    function submitProof(
        bytes memory _bankReceiptDec,
        bytes memory _y,
        bytes memory _proof
    ) external {
        require(msg.sender == bob, "Only Bob can submit proof.");
        require(address(this).balance >= totalAmount, "Insufficient balance.");
        // 这里需要根据实际的加密算法和验证逻辑实现验证过程
        bankReceiptDec = _bankReceiptDec;
        tre.y = _y;
        tre.proof = _proof;

        if (verifyProof()) {
            // 如果验证通过，Bob从合约中提取1.01a ETH
            payable(bob).transfer(totalAmount);
            emit TransferCompleted(bob, totalAmount);
        } else {
            payable(alice).transfer(totalAmount);
            emit TransferCompleted(alice, totalAmount);
        }
    }

    function verifyProof() internal view returns (bool) {
        // 1. if all is done, return true
        // 2. if the cipher is not correct, return true
        // 3. if signature cannot verify, return false
        // 4. if bankreceipt is not correct, return false

        return WesolowskiVDFVerifier.verifyVDF(
            tre.N, tre.x, tre.y, tre.proof, tre.delay
        );
    }

    function verifyBankReceipt() internal pure returns (bool) {
        return true;
    }

}