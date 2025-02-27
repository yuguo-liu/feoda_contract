// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Wesolowski-VDF/WesolowskiVDFVerifier.sol";
import "./AES/aes128-gcm.sol";
import "./ecdsa/FCL_ecdsa.sol";

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
    uint256 public amount;           // amount a
    uint256 public deposit;          // deposit 0.01a
    uint256 public totalAmount;      // total amount 1.01a
    uint256 public exchangeRate;     // exchange rate: required to get by Chainlink
    uint256 public contract_time;    // timestamp when contract is constructed (in sec)
    uint256 public timeout;          // timeout (in sec)
    
    bytes public bankReceiptEnc;     // the bank receipt (enc)
    bytes public bankReceiptDec;     // the bank receipt
    bool public isDepositToContract; // whether alice deposit the ETH to the contract
    bool public isUploadBankReceipt;

    Tre public tre;

    event Deposit(address indexed user, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event EncryptedDataUploaded(bytes encryptedData);
    event BankReceiptUploaded(bytes bankReceipt);
    event TransferCompleted(address indexed to, uint256 amount);

    constructor(address _bob, uint256 _amount, uint256 _exchangeRate, uint256 _timeout) {
        alice               = msg.sender;
        bob                 = _bob;                      
        amount              = _amount;
        deposit             = amount / 100;         
        totalAmount         = amount + deposit;  
        exchangeRate        = _exchangeRate;
        isDepositToContract = false;
        isUploadBankReceipt = false;
        timeout             = _timeout;
        contract_time       = block.timestamp;
    }

    function depositToContract() external payable {
        require(msg.sender == alice, "Only Alice can deposit.");
        require(msg.value == totalAmount, "Deposit amount must be more than 1.01a.");
        emit Deposit(msg.sender, msg.value);
        isDepositToContract = true;
    }

    function getTransactionInfo() external view returns (address, address, uint256, uint256, uint256, uint256, bool) {
        return (alice, bob, amount, deposit, totalAmount, exchangeRate, isDepositToContract);
    }

    function transferToBob() external {
        require(msg.sender == alice, "Only Alice can initiate transfer.");
        require(address(this).balance >= totalAmount, "Insufficient balance.");
        payable(bob).transfer(amount);
        payable(alice).transfer(deposit);
        emit Transfer(msg.sender, bob, amount);
        emit Transfer(msg.sender, alice, deposit);
        isDepositToContract = false;
    }

    function transferToAliceTimeout() external {
        require(msg.sender == alice, "Only Alice can initiate transfer.");
        require(address(this).balance >= totalAmount, "Insufficient balance.");
        require(block.timestamp >= contract_time + timeout, "not timeout yet");
        payable(alice).transfer(totalAmount);
        emit TransferCompleted(alice, totalAmount);
        isDepositToContract = false;
    }

    function uploadEncryptedData(
        bytes memory _c,
        bytes memory _x,
        bytes memory _N,
        uint256 security_param,
        uint _delay
    ) external {
        require(msg.sender == alice, "Only Alice can upload encrypted data.");
        tre.c              = _c;
        tre.x              = _x;
        tre.N              = _N;
        tre.delay          = _delay;
        tre.security_param = security_param;
        emit EncryptedDataUploaded(_c);
    }

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

    /*
        1. if vdf failed, pay to bob
        2. if signature failed, pay to bob
        3. if decryption failed, pay to alice
        4. if decrypted content is incorrect, pay to alice
        5. if decrypted content is correct, pay to bob
    */
    function submitProof(
        bytes memory _bankReceiptDec,
        bytes memory _y,
        bytes memory _proof
    ) external {
        require(msg.sender == bob, "Only Bob can submit proof.");
        require(address(this).balance >= totalAmount, "Insufficient balance.");

        bankReceiptDec = _bankReceiptDec;
        tre.y          = _y;
        tre.proof      = _proof;

        if (vdfVerify()) {
            
        } else {
            payable(bob).transfer(totalAmount);
            emit TransferCompleted(bob, totalAmount);
        }
    }

    function vdfVerify() internal view returns (bool) {
        return WesolowskiVDFVerifier.verifyVDF(
            tre.N, tre.x, tre.y, tre.proof, tre.delay
        );
    }

    function verifyBankReceipt() internal pure returns (bool) {
        return true;
    }

    function testSignature(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) external view returns (bool) {
        return FCL_ecdsa.ecdsa_verify(
            message,
            r, s, Qx, Qy
        );
    }

}