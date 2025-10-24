#include "../include/expand_key.h"

// helper function for file reading
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

// another helper function for file reading
uint8_t char_to_hex(char c) {
    switch (c) {
        case '0':
            return 0x00;
        case '1':
            return 0x01;
        case '2':
            return 0x02;
        case '3':
            return 0x03;
        case '4':
            return 0x04;
        case '5':
            return 0x05;
        case '6':
            return 0x06;
        case '7':
            return 0x07;
        case '8':
            return 0x08;
        case '9':
            return 0x09;
        case 'A':
            return 0x0A;
        case 'a':
            return 0x0A;
        case 'B':
            return 0x0B;
        case 'b':
            return 0x0B;
        case 'C':
            return 0x0C;
        case 'c':
            return 0x0C;
        case 'D':
            return 0x0D;
        case 'd':
            return 0x0D;
        case 'E':
            return 0x0E;
        case 'e':
            return 0x0E;
        case 'F':
            return 0x0F;
        case 'f':
            return 0x0F;
        default:
            fprintf(stderr, "Error: Invalid character [%c] in key file\n", c);
            exit(1);
        }

        return -1;
}

// returns the key length and puts the key from the file in an array of uint8_t
int read_key(char* key_file, uint8_t* key) {

    // open file
    FILE *f = fopen(key_file, "r");
    if (!f) {
        fprintf(stderr, "Error: failed to open %s\n", key_file);
        exit(1);
    }

    char buffer[BUFSIZ];

    int c;
    int i = 0;
    while ((c = fgetc(f)) != EOF)
        buffer[i++] = c;

    // remember to close file
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

// rotate a 4 byte word to the left
// 1,2,3,4 -> 2,3,4,1
uint32_t rot_word(uint32_t rot_me) {
    uint32_t byte1 = rot_me >> 24;
    rot_me <<= 8;
    return rot_me | byte1;
};

// apply s-box substitution to the provided word
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

// return the rcon lookup table value corresponding to the input
uint32_t rcon(uint32_t rcon_me) {
    return AES_RCON[rcon_me];
}

// return the specified 4 bytes of the expanded key
uint32_t EK(uint8_t* ekey, int len_ekey, int offset) {
    if (offset > len_ekey - 4)
        exit(1);
    uint32_t ret_val = (0x00000000 | ekey[offset]) << 24;
    ret_val |= (0x00000000 | ekey[offset + 1]) << 16;
    ret_val |= (0x00000000 | ekey[offset + 2]) << 8;
    ret_val |= ekey[offset + 3];
    return ret_val;
    
}

// return the specified 4 bytes of the key
uint32_t K(uint8_t* key, int len_key, int offset) {
    return EK((uint8_t*)key, len_key, offset);
}

// Store 4 bytes of the expanded key
void store_ekey(uint8_t* loc, uint32_t store_val) {
    loc[0] = store_val >> 24;
    loc[1] = (store_val & 0x00FF0000) >> 16;
    loc[2] = (store_val & 0x0000FF00) >> 8;
    loc[3] = store_val & 0x000000FF;
    
}

// utilize the above functions to complete the expand key algorithm
void expand_key(uint8_t* key, int len_key, uint8_t* ekey) {
    // Key length determines how many rounds to expand the key

    // Calculate useful variables
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
            store_ekey(ekey + round_num*4, sub_word(rot_word(EK(ekey, len_ekey, (round_num - 1)*4))) ^ rcon(round_num/(len_key/4) - 1) ^ EK(ekey, len_ekey, (round_num - (len_key/4))*4));
        } else if (len_key == 32 && round_num % 4 == 0) {
            store_ekey(ekey + round_num*4, sub_word(EK(ekey, len_ekey, (round_num - 1)*4)) ^ EK(ekey, len_ekey, (round_num - len_key/4)*4));
        } else {
            store_ekey(ekey + round_num*4, EK(ekey, len_ekey, (round_num - 1)*4) ^ EK(ekey, len_ekey, (round_num - (len_key/4))*4));
        }
         
        round_num++;
    }
}
