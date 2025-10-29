/*
 * -----------------------------------------------------------------------------
 * File: expand_key.c
 * Author: Jacob Bechtel
 *
 * Description:
 *   Implementation of the AES key expansion (Rijndael key schedule) and its
 *   supporting helper functions. This file handles reading and parsing keys
 *   from files, performing S-box and Rcon transformations, and generating
 *   the full expanded key used in encryption and decryption rounds.
 *
 * Details:
 *   Implements AES-128, AES-192, and AES-256 key schedule variants.
 *   Includes helper functions for:
 *     - Whitespace stripping and hex parsing from text key files
 *     - S-box substitution (SubWord)
 *     - Word rotation (RotWord)
 *     - Round constant lookup (Rcon)
 *     - Word packing/unpacking from byte arrays
 *
 * Attribution:
 *   This file's documentation was developed with assistance from
 *   OpenAI’s ChatGPT (GPT-5 model) to ensure correctness, readability, and
 *   consistency with AES standard specifications and the overall project style.
 *   All algorithmic logic and final verification were performed by the author.
 *
 * Date: October 2025
 * -----------------------------------------------------------------------------
 */

#include "../include/expand_key.h"

/* --------------------------------------------------------------------------
 * File Reading Utilities
 * -------------------------------------------------------------------------- */

/**
 * @brief Strip all whitespace characters from a NUL-terminated string in place.
 */
void strip_whitespace(char* s) {
    char *src = s, *dst = s;
    while (*src) {
        if (!isspace((unsigned char)*src)) {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

/**
 * @brief Convert a single hexadecimal character to its numeric 4-bit value.
 *        Exits on invalid input.
 */
uint8_t char_to_hex(char c) {
    switch (c) {
        case '0': return 0x00;
        case '1': return 0x01;
        case '2': return 0x02;
        case '3': return 0x03;
        case '4': return 0x04;
        case '5': return 0x05;
        case '6': return 0x06;
        case '7': return 0x07;
        case '8': return 0x08;
        case '9': return 0x09;
        case 'A': case 'a': return 0x0A;
        case 'B': case 'b': return 0x0B;
        case 'C': case 'c': return 0x0C;
        case 'D': case 'd': return 0x0D;
        case 'E': case 'e': return 0x0E;
        case 'F': case 'f': return 0x0F;
        default:
            fprintf(stderr, "Error: Invalid character [%c] in key file\n", c);
            exit(1);
        }

        return -1;
}
/* --------------------------------------------------------------------------
 * Key Reading
 * -------------------------------------------------------------------------- */

/**
 * @brief Read an ASCII hex key file, strip whitespace, and load bytes into key[].
 *        Supports AES-128/192/256 key lengths (16/24/32 bytes).
 */
int read_key(char* key_file, uint8_t* key) {

    FILE* f = fopen(key_file, "r");
    if (!f) {
        fprintf(stderr, "Error: failed to open %s\n", key_file);
        exit(1);
    }

    char buffer[BUFSIZ];

    int c;
    int i = 0;
    while ((c = fgetc(f)) != EOF)
        buffer[i++] = c;

    fclose(f);

    buffer[i] = '\0';
    
    strip_whitespace(buffer);

    i = 0;
    int i2 = 0;
    while (buffer[i2] != '\0' && buffer[i2 + 1] != '\0') {
        key[i++] = (char_to_hex(buffer[i2]) << 4) | char_to_hex(buffer[i2 + 1]);
        i2 += 2;
    }
    
    if (i != 16 && i != 24 && i != 32) {
        fprintf(stderr, "Error: Invalid key file length of %d\n", i);
        exit(1);
    }

    return i;
}
/* --------------------------------------------------------------------------
 * Rijndael Word Operations
 * -------------------------------------------------------------------------- */

/**
 * @brief Rotate a 32-bit word left by one byte: [b0 b1 b2 b3] → [b1 b2 b3 b0].
 */
uint32_t rot_word(uint32_t rot_me) {
    uint32_t byte1 = rot_me >> 24;
    rot_me <<= 8;
    return rot_me | byte1;
};

/**
 * @brief Apply AES S-box substitution to all bytes of a 32-bit word.
 */
uint32_t sub_word(uint32_t sub_me) {
    uint8_t s0 = sub_me >> 24;
    uint8_t s1 = (sub_me & 0x00FF0000) >> 16;
    uint8_t s2 = (sub_me & 0x0000FF00) >> 8;
    uint8_t s3 = sub_me & 0x000000FF;
    
    s0 = AES_SBOX[s0];
    s1 = AES_SBOX[s1];
    s2 = AES_SBOX[s2];
    s3 = AES_SBOX[s3];
    
    uint32_t ret_val = 0x00000000 | s0;
    ret_val <<= 8;
    ret_val |= s1;
    ret_val <<= 8;
    ret_val |= s2;
    ret_val <<= 8;
    ret_val |= s3;
    
    return ret_val;
}

/**
 * @brief Return the Rcon value for a given round index.
 */
uint32_t rcon(uint32_t rcon_me) {
    return AES_RCON[rcon_me];
}

/* --------------------------------------------------------------------------
 * Key and Expanded Key Access
 * -------------------------------------------------------------------------- */

/**
 * @brief Extract 4 bytes from expanded key array as a big-endian 32-bit word.
 */
uint32_t EK(uint8_t* ekey, int len_ekey, int offset) {
    if (offset > len_ekey - 4)
        exit(1);
    uint32_t ret_val = (0x00000000 | ekey[offset]) << 24;
    ret_val |= (0x00000000 | ekey[offset + 1]) << 16;
    ret_val |= (0x00000000 | ekey[offset + 2]) << 8;
    ret_val |= ekey[offset + 3];
    return ret_val;
    
}

/**
 * @brief Extract 4 bytes from the original key array (wrapper over EK()).
 */
uint32_t K(uint8_t* key, int len_key, int offset) {
    return EK((uint8_t*)key, len_key, offset);
}

/**
 * @brief Store a 32-bit word as 4 bytes (big-endian) at the target location.
 */
void store_ekey(uint8_t* loc, uint32_t store_val) {
    loc[0] = store_val >> 24;
    loc[1] = (store_val & 0x00FF0000) >> 16;
    loc[2] = (store_val & 0x0000FF00) >> 8;
    loc[3] = store_val & 0x000000FF;
    
}

/* --------------------------------------------------------------------------
 * AES Key Expansion
 * -------------------------------------------------------------------------- */

/**
 * @brief Perform the AES key schedule expansion.
 *
 * Expands 16-, 24-, or 32-byte cipher keys into the full round key array.
 */
void expand_key(uint8_t* key, int len_key, uint8_t* ekey) {
    
    // Key length determines how many rounds to expand the key
    int round_num = 0;
    int num_rounds = len_key + 28;
    int len_ekey = num_rounds*4;

    // Initial Rounds
    // Expanded key is the same as the key for the first 4-8 rounds, depending on the key length
    for (int i = 0; i < len_key/4; i++) {
        store_ekey(ekey + round_num*4, K(key, len_key, round_num*4));
        round_num++;
    }
    
    // Remaining Rounds
    // Every 4, 6 or 8 rounds, perform the complex function, otherwise xor with previous bytes
    while (round_num < num_rounds) {
        if (round_num % (len_key/4) == 0) {
            store_ekey(ekey + round_num*4, 
                sub_word(rot_word(EK(ekey, len_ekey, (round_num - 1)*4))) ^ 
                rcon(round_num/(len_key/4) - 1) ^ 
                EK(ekey, len_ekey, (round_num - (len_key/4))*4));
        } else if (len_key == 32 && round_num % 4 == 0) {
            store_ekey(ekey + round_num*4, 
                sub_word(EK(ekey, len_ekey, (round_num - 1)*4)) ^ 
                EK(ekey, len_ekey, (round_num - len_key/4)*4));
        } else {
            store_ekey(ekey + round_num*4, 
                EK(ekey, len_ekey, (round_num - 1)*4) ^ 
                EK(ekey, len_ekey, (round_num - (len_key/4))*4));
        }
         
        round_num++;
    }
}
