// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./lib/GenesisUtils.sol";
import "./interfaces/ICircuitValidator.sol";
import "./verifiers/ZKPVerifier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Verifier is ZKPVerifier {
    using ECDSA for bytes32;
    uint64 public constant TRANSFER_REQUEST_ID = 1;

    mapping(address => bool) allowed;
    mapping(uint256 => uint256) reputation;
    mapping(uint256 => uint256) timestamp;
    mapping(address => uint128) ids;
    address private _issuerAddress;
    address public ownerAddress;
    uint128 public noOfUsers = 0;

    constructor() {
        _issuerAddress = _msgSender();
        ownerAddress = _msgSender();
    }

    modifier onlyAdmin() {
        require(msg.sender == ownerAddress, "only admin");
        _;
    }

    function _beforeProofSubmit(
        uint64, /* requestId */
        uint256[] memory inputs,
        ICircuitValidator validator
    ) internal view override {
        // check that the challenge input of the proof is equal to the msg.sender
        address addr = GenesisUtils.int256ToAddress(
            inputs[validator.getChallengeInputIndex()]
        );
        require(
            _msgSender() == addr,
            "address in the proof is not a sender address"
        );
    }

    modifier verify(
        bytes memory signature,
        uint256 application,
        uint256 _amount
    ) {
        bytes32 digest = keccak256(abi.encode(application, _amount));
        digest = digest.toEthSignedMessageHash();
        address signer = ECDSA.recover(digest, signature);
        require(signer == ownerAddress, "Invalid signature");
        _;
    }

    function setIssuerAddress(address issuerAddress) public onlyAdmin {
        _issuerAddress = issuerAddress;
    }

    function _afterProofSubmit(
        uint64 requestId,
        uint256[] memory inputs,
        ICircuitValidator validator
    ) internal override {
        require(
            requestId == TRANSFER_REQUEST_ID,
            "proof can not be submitted more than once"
        );

        uint256 id = inputs[validator.getChallengeInputIndex()];

        if (allowed[_msgSender()] == false) {
            allowed[_msgSender()] = true;
        }
    }

    function verifyAndUpdateReputation(
        uint256 application,
        uint256 _amount,
        bytes memory signature
    ) external verify(signature, application, _amount) {
        require(
            allowed[_msgSender()] == true,
            "You're not allowed to access this function"
        );
        allowed[_msgSender()] = false;
        if (ids[_msgSender()] == 0) {
            ids[_msgSender()] = noOfUsers;
            noOfUsers++;
        }
        reputation[ids[_msgSender()] * 10 + application] = _amount;
        timestamp[reputation[ids[_msgSender()] * 10 + application]] = block
            .timestamp;
    }
}
