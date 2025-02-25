// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BigNumber.sol";

library WesolowskiVDFVerifier {

    function verifyVDF(
        bytes memory n,
        bytes memory input_param,
        bytes memory output_param,
        bytes memory proof,
        uint delay
    ) public view returns (bool) {
        bytes memory prime_l = flat_shamir_hash(input_param, output_param);
        BigNumber memory prime_l_bn = BigNumbers.init(prime_l, false);
        BigNumber memory delay_bn = BigNumbers.init(delay, false);
        BigNumber memory proof_bn = BigNumbers.init(proof, false);
        BigNumber memory n_bn = BigNumbers.init(n, false);
        BigNumber memory input_bn = BigNumbers.init(input_param, false);
        BigNumber memory output_bn = BigNumbers.init(output_param, false);

        BigNumber memory TWO = BigNumbers.init(2, false);
        BigNumber memory r = BigNumbers.modexp(TWO, delay_bn, prime_l_bn);
        BigNumber memory proof_exp = BigNumbers.modexp(proof_bn, prime_l_bn, n_bn);
        BigNumber memory input_exp = BigNumbers.modexp(input_bn, r, n_bn);
        BigNumber memory cmp = BigNumbers.modmul(proof_exp, input_exp, n_bn);
        return BigNumbers.eq(output_bn, cmp);
    }

    function flat_shamir_hash(
        bytes memory g,
        bytes memory y
    ) internal pure returns (bytes memory) {
        bytes memory params = bytes.concat(g, y);
        bytes32 hash = sha256(params);
        bytes1 firstByte = bytes1(hash);
        uint8 firstDigit = uint8(firstByte) >> 4;
        uint256 prime = next_prime(firstDigit);
        return abi.encodePacked(prime);
    }

    function next_prime(
        uint8 number
    ) internal pure returns (uint256) {
        uint256 prime;
        if (number == 0 || number == 1 || number == 2) prime = 2;
        else if (number == 3) prime = 3;
        else if (number == 4 || number == 5) prime = 5;
        else if (number == 6 || number == 7) prime = 7;
        else if (number == 8 || number == 9 || number == 10 || number == 11) prime = 11;
        else if (number == 12 || number == 13) prime = 13;
        else if (number == 14 || number == 15) prime = 17;
        else prime = 17;
        return prime;
    }
}