/**
* utils:
* - aes in solidity: https://github.com/yylluu/my-crypto-tools-solidity/blob/master/aes128.sol
* - byteslib (slice) in solidity: https://stackoverflow.com/questions/74443594/how-to-slice-bytes-memory-in-solidity
*/
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library GF128 {
    // 128 bit addition - xor operation
    function add(uint128 a, uint128 b) pure internal returns (uint128) {
        return a ^ b;
    }

    // 128 bit multiplication - modular
    // Reduced polynomial is 0x87 (i.e. x^8 + x^7 + x^6 + x^4 + x^3 + x^1 + 1)
    function mul(uint128 a, uint128 b) pure internal returns (uint128) {
        uint128 result = 0;
        uint128 modulus = 0x87;  // Reduced polynomial of AES

        for (uint8 i = 0; i < 128; i++) {
            if (b & 1 != 0) {
                result ^= a;  // if the lsb of b is 1, added by a
            }
            // step of multiply: left shift a and check whether to be mod
            bool high_bit_set = (a >> 127) != 0;
            a <<= 1;
            if (high_bit_set) {
                a ^= modulus;  // if the msb of a is 1, subtracted by modulus
            }
            b >>= 1;  // b shift left by 1 bit
        }
        return result;
    }
}

library BytesLib {  
  function slice(
        bytes memory _bytes,
        uint256 _start,
        uint256 _length
    )
        internal
        pure
        returns (bytes memory)
    {
        require(_length + 31 >= _length, "slice_overflow");
        require(_bytes.length >= _start + _length, "slice_outOfBounds");

        bytes memory tempBytes;

        // Check length is 0. `iszero` return 1 for `true` and 0 for `false`.
        assembly {
            switch iszero(_length)
            case 0 {
                // Get a location of some free memory and store it in tempBytes as
                // Solidity does for memory variables.
                tempBytes := mload(0x40)

                // Calculate length mod 32 to handle slices that are not a multiple of 32 in size.
                let lengthmod := and(_length, 31)

                // tempBytes will have the following format in memory: <length><data>
                // When copying data we will offset the start forward to avoid allocating additional memory
                // Therefore part of the length area will be written, but this will be overwritten later anyways.
                // In case no offset is require, the start is set to the data region (0x20 from the tempBytes)
                // mc will be used to keep track where to copy the data to.
                let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
                let end := add(mc, _length)

                for {
                    // Same logic as for mc is applied and additionally the start offset specified for the method is added
                    let cc := add(add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))), _start)
                } lt(mc, end) {
                    // increase `mc` and `cc` to read the next word from memory
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    // Copy the data from source (cc location) to the slice data (mc location)
                    mstore(mc, mload(cc))
                }

                // Store the length of the slice. This will overwrite any partial data that 
                // was copied when having slices that are not a multiple of 32.
                mstore(tempBytes, _length)

                // update free-memory pointer
                // allocating the array padded to 32 bytes like the compiler does now
                // To set the used memory as a multiple of 32, add 31 to the actual memory usage (mc) 
                // and remove the modulo 32 (the `and` with `not(31)`)
                mstore(0x40, and(add(mc, 31), not(31)))
            }
            // if we want a zero-length slice let's just return a zero-length array
            default {
                tempBytes := mload(0x40)
                // zero out the 32 bytes slice we are about to return
                // we need to do it because Solidity does not garbage collect
                mstore(tempBytes, 0)

                // update free-memory pointer
                // tempBytes uses 32 bytes in memory (even when empty) for the length.
                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }
}

contract AES128_GCM {
    
    //event State(uint8[4][4] state);
    using GF128 for uint128;
    using BytesLib for bytes;
    
    uint8 [11] RCON = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    
    uint8 [256] SBOX =  
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
         0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
         0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
         0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
         0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
         0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
         0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
         0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
         0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
         0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
         0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
         0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
         0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
         0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
         0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
         0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
    
    uint8 [256] INV_SBOX = 
        [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
         0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
         0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
         0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
         0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
         0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
         0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
         0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
         0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
         0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
         0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
         0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
         0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
         0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
         0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
         0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];
    
    uint8 [256] LOG =
        [0x00, 0x00, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
         0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
         0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
         0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
         0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4, 0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
         0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13, 0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
         0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12, 0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
         0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56, 0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
         0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3, 0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
         0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf, 0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
         0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67, 0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
         0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34, 0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
         0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7, 0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
         0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a, 0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
         0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c, 0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
         0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0, 0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38];

    uint8 [256] EXP =
        [0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
         0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
         0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
         0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d, 0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
         0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f, 0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
         0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85, 0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
         0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
         0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
         0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
         0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
         0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84, 0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
         0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2, 0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
         0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c, 0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
         0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
         0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
         0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01];
    

    function aes_dec (uint8[16] memory cipher, uint8[16] memory key) public view returns (uint8 [16] memory) {
        uint8[4][4] memory state =
        [
            [cipher[0], cipher[4], cipher[8], cipher[12]],
            [cipher[1], cipher[5], cipher[9], cipher[13]],
            [cipher[2], cipher[6], cipher[10], cipher[14]],
            [cipher[3], cipher[7], cipher[11], cipher[15]]
        ];
        uint8 [4][44] memory expanded_key = expand_key(key);
        // round 11
        uint8 [4][4] memory round_key = [expanded_key[40],expanded_key[41],expanded_key[42],expanded_key[43]];
        state = add_round_key(state, round_key);
        // round 10 ~ 1
        for (uint r = 9; r >= 1; r--) {
            state = inv_shift_rows(state);
            //emit State(state);
            state = inv_sub_state(state);
            //emit State(state);
            round_key = [expanded_key[4*r],expanded_key[4*r+1],expanded_key[4*r+2],expanded_key[4*r+3]];
            state = add_round_key(state, round_key);
            //emit State(state);
            state = inv_mix_columns(state);
            //emit State(state);
        }
        // round 0x0
        state = inv_shift_rows(state);
        state = inv_sub_state(state);
        round_key = [expanded_key[0],expanded_key[1],expanded_key[2],expanded_key[3]];
        state = add_round_key(state, round_key);
        uint8[16] memory plain = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        for (uint i = 0; i < 4; i++) {
            for (uint j = 0; j < 4; j++) {
                plain[4*i + j] = state[j][i];
            }
        }
        return plain;
    }
    
    function add_round_key(uint8 [4][4] memory state, uint8 [4][4] memory round_key) private pure returns (uint8 [4][4] memory) {
        for (uint i = 0; i < 4; i++) {
            for (uint j = 0; j < 4; j++) {
                state[i][j] = state[i][j] ^ round_key[j][i];
            }
        }
        return state;
    }
    
    function inv_shift_rows(uint8 [4][4] memory state) private pure returns (uint8 [4][4] memory) {
        uint8[4] memory s_0 = state[0];
        uint8[4] memory s_1 = [state[1][3], state[1][0], state[1][1], state[1][2]];
        uint8[4] memory s_2 = [state[2][2], state[2][3], state[2][0], state[2][1]];
        uint8[4] memory s_3 = [state[3][1], state[3][2], state[3][3], state[3][0]];
        return [s_0, s_1, s_2, s_3];
    }
    
    function inv_sub_state(uint8 [4][4] memory state) private view returns (uint8 [4][4] memory) {
        for (uint i = 0; i < 4; i++) {
            for (uint j = 0; j < 4; j++) {
                state[i][j] = INV_SBOX[state[i][j]];
            }
        }
        return state; 
    }
    
    function inv_mix_columns(uint8 [4][4] memory state) private view returns (uint8 [4][4] memory) {
        uint8[4][4] memory cpy = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
        for (uint i = 0; i < 4; i++) {
            for (uint row = 0; row < 4; row++) {
                cpy[row][i] = state[row][i];
            }
            state[0][i] = gal_mul(cpy[0][i], 14) ^ gal_mul(cpy[3][i], 9) ^ gal_mul(cpy[2][i], 13) ^ gal_mul(cpy[1][i], 11);
            state[1][i] = gal_mul(cpy[1][i], 14) ^ gal_mul(cpy[0][i], 9) ^ gal_mul(cpy[3][i], 13) ^ gal_mul(cpy[2][i], 11);
            state[2][i] = gal_mul(cpy[2][i], 14) ^ gal_mul(cpy[1][i], 9) ^ gal_mul(cpy[0][i], 13) ^ gal_mul(cpy[3][i], 11);
            state[3][i] = gal_mul(cpy[3][i], 14) ^ gal_mul(cpy[2][i], 9) ^ gal_mul(cpy[1][i], 13) ^ gal_mul(cpy[0][i], 11);
        }
        return state;
    }
    
    function gal_mul(uint8 x, uint8 y) private view returns (uint8) {
        if (x == 0 || y == 0) {
            return 0;
        }
        uint16 x_log = LOG[x];
        uint16 y_log = LOG[y];
        uint16 exp_val = (x_log + y_log) % 255;
        return EXP[exp_val];
    }

    function expand_key(uint8[16] memory key) private view returns (uint8 [4][44] memory) {
        uint8 [4][44] memory w;
        w[0][0] = key[0];
        w[0][1] = key[1];
        w[0][2] = key[2];
        w[0][3] = key[3];
        w[1][0] = key[4];
        w[1][1] = key[5];
        w[1][2] = key[6];
        w[1][3] = key[7];
        w[2][0] = key[8];
        w[2][1] = key[9];
        w[2][2] = key[10];
        w[2][3] = key[11];
        w[3][0] = key[12];
        w[3][1] = key[13];
        w[3][2] = key[14];
        w[3][3] = key[15];
        for (uint i = 4; i < 44; i++) {
            uint8[4] memory tmp = w[i-1];
            if ((i % 4) == 0) {
                tmp = sub_word(rot_word(tmp));
                tmp[0] = tmp[0] ^ RCON[i/4];
            }
            w[i] = [tmp[0] ^ w[i-4][0], tmp[1] ^ w[i-4][1], tmp[2] ^ w[i-4][2], tmp[3] ^ w[i-4][3]];
        }
        return w;
    }
    
    function rot_word (uint8[4] memory w) private pure returns (uint8[4] memory) {
        uint8[4] memory new_w = [0,0,0,0];
        new_w[0] = w[1];
        new_w[1] = w[2];
        new_w[2] = w[3];
        new_w[3] = w[0];
        return new_w;
    }
    
    function sub_word (uint8[4] memory w) private view returns (uint8[4] memory) {
        w[0] = SBOX[w[0]];
        w[1] = SBOX[w[1]];
        w[2] = SBOX[w[2]];
        w[3] = SBOX[w[3]];
        return w;
    }
    
    function shift_rows(uint8 [4][4] memory state) private pure returns (uint8 [4][4] memory) {
        uint8[4] memory s_0 = state[0];
        uint8[4] memory s_1 = [state[1][1], state[1][2], state[1][3], state[1][0]];
        uint8[4] memory s_2 = [state[2][2], state[2][3], state[2][0], state[2][1]];
        uint8[4] memory s_3 = [state[3][3], state[3][0], state[3][1], state[3][2]];
        return [s_0, s_1, s_2, s_3];
    }

    function sub_state(uint8 [4][4] memory state) private view returns (uint8 [4][4] memory) {
        for (uint i = 0; i < 4; i++) {
            for (uint j = 0; j < 4; j++) {
                state[i][j] = SBOX[state[i][j]];
            }
        }
        return state; 
    }

    function mix_columns(uint8 [4][4] memory state) private view returns (uint8 [4][4] memory) {
        uint8[4][4] memory cpy = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
        for (uint i = 0; i < 4; i++) {
            for (uint row = 0; row < 4; row++) {
                cpy[row][i] = state[row][i];
            }
            state[0][i] = gal_mul(cpy[0][i], 2) ^ gal_mul(cpy[1][i], 3) ^ gal_mul(cpy[2][i], 1) ^ gal_mul(cpy[3][i], 1);
            state[1][i] = gal_mul(cpy[0][i], 1) ^ gal_mul(cpy[1][i], 2) ^ gal_mul(cpy[2][i], 3) ^ gal_mul(cpy[3][i], 1);
            state[2][i] = gal_mul(cpy[0][i], 1) ^ gal_mul(cpy[1][i], 1) ^ gal_mul(cpy[2][i], 2) ^ gal_mul(cpy[3][i], 3);
            state[3][i] = gal_mul(cpy[0][i], 3) ^ gal_mul(cpy[1][i], 1) ^ gal_mul(cpy[2][i], 1) ^ gal_mul(cpy[3][i], 2);
        }
        return state;
    }

    function aes_enc(uint8[16] memory plain, uint8[16] memory key) public view returns (uint8[16] memory) {
        uint8[4][4] memory state = [
            [plain[0], plain[4], plain[8], plain[12]],
            [plain[1], plain[5], plain[9], plain[13]],
            [plain[2], plain[6], plain[10], plain[14]],
            [plain[3], plain[7], plain[11], plain[15]]
        ];
        // expand the key
        uint8[4][44] memory expanded_key = expand_key(key);
        // round 0
        uint8[4][4] memory round_key = [expanded_key[0], expanded_key[1], expanded_key[2], expanded_key[3]];
        state = add_round_key(state, round_key);
        state = sub_state(state);
        state = shift_rows(state);
        // round 1 ~ 10
        for (uint r = 1; r <= 9; r++) {
            state = mix_columns(state);
            round_key = [expanded_key[4*r], expanded_key[4*r+1], expanded_key[4*r+2], expanded_key[4*r+3]];
            state = add_round_key(state, round_key);
            state = sub_state(state);
            state = shift_rows(state);
        }
        // round 11
        round_key = [expanded_key[40], expanded_key[41], expanded_key[42], expanded_key[43]];
        state = add_round_key(state, round_key);

        uint8[16] memory cipher = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        for (uint i = 0; i < 4; i++) {
            for (uint j = 0; j < 4; j++) {
                cipher[4*i + j] = state[j][i];
            }
        }

        return cipher;
    }

    function bytes_to_uint128_array_w_padding(bytes memory in_bytes) public pure returns(uint128[] memory) {
        uint length = in_bytes.length;
        uint padding_length = 16 - length % 16;
        if (padding_length == 16) padding_length = 0;

        bytes memory padding = hex"00";
        for (uint i = 1; i < padding_length; i++) {
            padding = bytes.concat(padding, hex"00");
        }

        bytes memory padded_in = bytes.concat(in_bytes, padding);
        
        uint num_block = padded_in.length / 16;
        uint128[] memory uint128_array = new uint128[](num_block);

        for (uint i = 0; i < num_block; i++) {
            uint128_array[i] = uint128(bytes16(BytesLib.slice(padded_in, i * 16, 16)));
        }

        return uint128_array;
    }

    function uint128_array_to_bytes(uint128[] memory uint128_array) public pure returns(bytes memory) {
        bytes memory uint128_bytes = abi.encodePacked(bytes16(uint128_array[0]));
        for (uint i = 1; i < uint128_array.length; i++) {
            uint128_bytes = bytes.concat(uint128_bytes, abi.encodePacked(uint128_array[1]));
        }
        return uint128_bytes;
    }

    function aes_gcm_dec(
        bytes memory cipher,
        bytes memory key,
        bytes memory iv,
        bytes memory auth_data
    ) public view returns (bytes memory plain) {

    }
}