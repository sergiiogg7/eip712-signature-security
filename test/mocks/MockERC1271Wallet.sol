// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @notice Minimal smart-contract wallet: a signature is valid when its ECDSA signer is `walletOwner`.
///         Same idea as a 1-of-1 Safe. Used to test ERC-1271 validation.
contract MockERC1271Wallet is IERC1271 {
    address public immutable walletOwner;

    constructor(address owner_) {
        walletOwner = owner_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && signer == walletOwner) return IERC1271.isValidSignature.selector;
        return 0xffffffff;
    }
}
