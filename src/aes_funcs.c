#include "../include/aes_funcs.h"

void usage(int exit_code) {
    if (exit_code != 0)
        printf("Invalid input\n");
    printf("aes [-e/d] [KEY_FILE] [VECTOR_FILE]\n");
    exit(exit_code);
}

int read_vector(char* vector_file, uint8_t* vector) {
    // TODO: make this a real fuction that gets more than just a single 16 byte vector
    return read_key(vector_file, vector);
}

void add_round_key(uint8_t* state, uint8_t* ekey, int offset) {
    for (int i = 0; i < 16; i++)
        state[i] = state[i] ^ ekey[i + offset*16];
}

void byte_sub(uint8_t* state, bool is_encrypt) {
    if (is_encrypt)
        for(int i = 0; i < 16; i++)
            state[i] = AES_SBOX[state[i]];
    else
        for(int i = 0; i < 16; i++)
            state[i] = AES_INV_SBOX[state[i]];
}

void shift_row(uint8_t* state, bool is_encrypt) {
    uint8_t temp[16];
    for(int i = 0; i < 16; i++)
        temp[i] = state[i];
    
    if (is_encrypt) {
        state[1]  = temp[5];
        state[5]  = temp[9];        
        state[9]  = temp[13];        
        state[13] = temp[1];

        state[2]  = temp[10];
        state[6]  = temp[14];        
        state[10] = temp[2];        
        state[14] = temp[6];
        
        state[3]  = temp[15];
        state[7]  = temp[3];        
        state[11] = temp[7];        
        state[15] = temp[11];
    } else {
        state[1]  = temp[13];
        state[5]  = temp[1];        
        state[9]  = temp[5];        
        state[13] = temp[9];

        state[2]  = temp[10];
        state[6]  = temp[14];        
        state[10] = temp[2];        
        state[14] = temp[6];
        
        state[3]  = temp[7];
        state[7]  = temp[11];        
        state[11] = temp[15];        
        state[15] = temp[3];
    }

}

uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0)
        return 0;
    else if (a == 1)
        return b;
    else if (b == 1)
        return a;
    
    a = AES_L[a];
    b = AES_L[b];

    uint16_t c = a + b;

    c = (c > 0xFF) ? c - 0xFF : c;
    
    return AES_E[c]; 
}

void mix_column(uint8_t* state, bool is_encrypt) {
    const uint8_t (*mul_mat)[4] = is_encrypt ? AES_MUL_E : AES_MUL_D;
    uint8_t temp[16];

    for (int i = 0; i < 16; i++) {
        int state_col = i/4;
        int mul_mat_row = i % 4;
        temp[i] = gf_mul(state[state_col*4], mul_mat[mul_mat_row][0]);
        
        for (int j = 1; j < 4; j++)
            temp[i] ^= gf_mul(state[state_col*4 + j], mul_mat[mul_mat_row][j]);
    }
    for (int i = 0; i < 16; i++)
        state[i] = temp[i];
}

void aes(uint8_t* state, uint8_t* key, int len_key, bool is_encrypt) {
    uint8_t ekey[240];
    expand_key(key, len_key, ekey);

    int round_num;

    // Calculate number of rounds
    int num_rounds = len_key/4 + 6;
    
    // Loop for all other than the last round, order of funcs depends on encryption/decryption
    if (is_encrypt) {
        round_num = 0;
        add_round_key(state, ekey, round_num);
        for (; round_num < num_rounds - 1; round_num++) {
            byte_sub(state, is_encrypt);
            shift_row(state, is_encrypt);
            mix_column(state, is_encrypt);
            add_round_key(state, ekey, round_num + 1);
        }
        byte_sub(state, is_encrypt);
        shift_row(state, is_encrypt);
        add_round_key(state, ekey, round_num + 1);
        
    } else {
        round_num = num_rounds - 1;
        add_round_key(state, ekey, round_num + 1);
        for (; round_num > 0; round_num--) {
            shift_row(state, is_encrypt);
            byte_sub(state, is_encrypt);
            add_round_key(state, ekey, round_num);
            mix_column(state, is_encrypt);

        }
        shift_row(state, is_encrypt);
        byte_sub(state, is_encrypt);
        add_round_key(state, ekey, round_num);

    }
    
}

void print_uint8_t_array(uint8_t* arr, int len_arr, char* result) {
    for (int i = 0; i < len_arr; i++) {
        sprintf(result, "%02x", arr[i]);
        result += 2;
        if (i % 4 == 0 && i != 0)
            sprintf(result++, " ");
    }
}
