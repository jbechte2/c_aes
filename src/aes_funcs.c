#include "../include/aes_funcs.h"

void usage(int exit_code) {
    if (exit_code != 0)
        printf("Invalid input\n");
    printf("USAGE: aes [OPTIONS] [KEY_FILE] [VECTOR_FILE]");
    exit(exit_code);
}

uint8_t* read_vector(char* vector_file, uint64_t* size, bool is_encrypt) {
    
    FILE* f = fopen(vector_file, "rb");
    if (!f) {
        fprintf(stderr, "Error: failed to open %s\n", vector_file);
        exit(1);
    }
    
    uint64_t capacity = BUFSIZ * sizeof(uint8_t);
    uint8_t* vector = malloc(capacity);
    
    int c;
    while ((c = fgetc(f)) != EOF) {
        // Unknown file size, so use realloc to dynamically grow the buffer
        // Use exponential scaling
        if ((*size) + 1 >= capacity) {
            capacity *= 2;
            uint8_t* bigger_vector = realloc(vector, capacity);
            vector = bigger_vector;
        }
        vector[(*size)++] = (uint8_t)c;
    }

    fclose(f);

    /* Pad out to a multiple of 16 bytes with the number of padded bytes 
     * per the PKCS standard for CBC, only for encryption
     */
    if (is_encrypt) {
        uint8_t pad_bytes = *size % 16 == 0 ? 16 : 16 - (*size % 16);
        //printf("size = %ld\npad_bytes = %d\n", *size, pad_bytes);
        for (int i = 0; i < pad_bytes; i++)
            vector[(*size)++] = pad_bytes;

        // Realloc smaller to fit the exact memory used for the vector
        uint8_t* smaller_vector = realloc(vector, (*size));

        // TODO: make this less jank
        if (!smaller_vector)
            exit(1);
    
        vector = smaller_vector;
    }
    
    return vector;
}

void add_round_key(uint8_t* state, uint8_t* ekey, int offset) {
    for (int i = 0; i < 16; i++) {
        //printf("add_round_key i:%d\n", i);
        state[i] = state[i] ^ ekey[i + offset*16];
    }
}

void byte_sub(uint8_t* state, bool is_encrypt) {

    // If encrypting, use the S-Box
    if (is_encrypt)
        for(int i = 0; i < 16; i++)
            state[i] = AES_SBOX[state[i]];

    // If decrypting, use the inverse S-Box
    else
        for(int i = 0; i < 16; i++)
            state[i] = AES_INV_SBOX[state[i]];
}

void shift_row(uint8_t* state, bool is_encrypt) {
    uint8_t temp[16];
    for(int i = 0; i < 16; i++)
        temp[i] = state[i];
    
    // Hardcoded shift rows due to rearranging the state array being slower and more annoying to code
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
    if (a == 0 || b == 0) return 0;
    else if (a == 1) return b;
    else if (b == 1) return a;
    
    a = AES_L[a];
    b = AES_L[b];

    uint16_t c = a + b;

    c = (c > 0xFF) ? c - 0xFF : c;
    
    return AES_E[c];
}

void mix_column(uint8_t* state, bool is_encrypt) {

    // Choose which matrix to use depending on encryption or decryption. All other steps are identical
    const uint8_t (*mul_mat)[4] = is_encrypt ? AES_MUL_E : AES_MUL_D;

    uint8_t temp[16];

    for (int i = 0; i < 16; i++) {
        
        int state_col = i/4;
        int mul_mat_row = i % 4;

        // Inital gf_mul done outside of the loop below as temp[i] needs to be set to something before XOR
        temp[i] = gf_mul(state[state_col*4], mul_mat[mul_mat_row][0]);
        
        for (int j = 1; j < 4; j++)
            temp[i] ^= gf_mul(state[state_col*4 + j], mul_mat[mul_mat_row][j]);
    }

    // Store the result in state
    for (int i = 0; i < 16; i++)
        state[i] = temp[i];
}

void aes(uint8_t* state, uint8_t* ekey, int len_key, bool is_encrypt) {
    int round_num = 0;

    // Calculate number of rounds
    int num_rounds = len_key/4 + 6;
    
    // Loop for all other than the last round, order of funcs depends on encryption/decryption
    if (is_encrypt) {
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
        // Use round_num as a countdown for decryption
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
        if (i % 4 == 0 && i != 0) {
            sprintf(result, " ");
            result++;
        }
        sprintf(result, "%.2x", arr[i]);
        result += 2*sizeof(char);
    }
}
