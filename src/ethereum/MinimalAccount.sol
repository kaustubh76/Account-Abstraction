// SPDX-License-Identifier:MIT

pragma solidity ^0.8.24;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract MinimalAccount is IAccount , Ownable {
    error MinimalAccount_NotFromEntryPoint();
    error MinimalAccount_NotFromEntryPointOrOwner();
    error MinimalAccount_CallFailed(bytes);
    IEntryPoint private immutable i_entryPoint;

    modifier requireFromEntryPoint() {
        if(msg.sender != address(i_entryPoint)) {
            revert MinimalAccount_NotFromEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner(){
        revert MinimalAccount_NotFromEntryPointOrOwner();
    }
    //             FUNCTIONS
    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    recieve() external payable {}

    //            EXTERNAL FUNCTIONS
    function execute(address dest, uint value, bytes calldata functionData) external requireFromEntryPoint {
        (bool success,  bytes memory result) = dest.call{value: value}(functionData);
        if(!success){
            revert MinimalAccount_CallFailed(result);
        }
    }
        

    // A signature is valid , if it's the MininalAccount owner
     function validateUserOp( PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds  external returns (uint256 validationData){
       validationData =  _validateSignature(userOp , userOpHash);
       // _validateNonce()
       _payPrefund(missingAccountFunds);
    }

    // EIP-191 version of the signed hash
    function _validateSignature(PackedUserOperation calldata userOp , bytes32 userOpHash) internal view returns(uint256 validationData) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash , userOp.signature); // who did the signature
        if(signer != owner()) {
                return SIG_VALIDATION_FAILED;
                }
            return SIG_VALIDATION_SUCCESS;
     }
    
    function _payPrefund(uint256 missingAccountFunds) internal {
        if(missingAccountFunds != 0) {
            (bool success, ) = msg.sender.call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
    }

    //            GETTERS

    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }
}