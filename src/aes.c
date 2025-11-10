#include "../include/aes_funcs.h"
#include "../include/expand_key.h"

int main (int argc, char *argv[]) {
    // Parse command line arguments
    if (argc < 3)
        usage(1);
    
    // Delare variables to be assigned by command line arguments
    bool is_encrypt = true;
    Op_mode op_mode = ECB;
    char outfile[BUFSIZ] = "output";

    char arg[BUFSIZ];
    for (int i = 1; i < argc - 2; i++) {
        arg[0] = '\0';
        strcpy(arg, argv[i]);
        if (!strcmp(arg, "-u") || !strcmp(arg, "--usage") || 
                !strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(0);
        } else if (!strcmp(arg, "-e")) {
            is_encrypt = true;
        } else if (!strcmp(arg, "-d")) {
            is_encrypt = false;
        } else if (!strcmp(arg, "--mode") || !strcmp(arg, "-m")) {
            arg[0] = '\0';
            strcpy(arg, argv[++i]);
            if (!strcmp(arg, "ECB")) op_mode = ECB;
            else if (!strcmp(arg, "CBC")) op_mode = CBC;
            else if (!strcmp(arg, "CFB")) op_mode = CFB;
            else if (!strcmp(arg, "OFB")) op_mode = OFB;
            else if (!strcmp(arg, "CTR")) op_mode = CTR;
            else usage(1);
        } else if (!strcmp(arg, "-o")) {
            outfile[0] = '\0';
            strcpy(outfile, argv[++i]);
        } else {
            usage(1);
        }
    }

    char* key_file = argv[argc - 2];
    char* vector_file = argv[argc - 1];

     
    uint8_t* key  = malloc(sizeof(uint8_t) * (32 + 1));
    if (!key) {
        fprintf(stderr, "Key failed to allocate.\n");
        exit(1);
    }

    int len_key = read_key(key_file, key);

    uint8_t* ekey = malloc(sizeof(uint8_t) * 240);
    if (!ekey) {
        fprintf(stderr, "Expanded Key failed to allocate.\n");
        free(key);
        exit(1);
    }

    expand_key(key, len_key, ekey);

    uint64_t *len_vector = malloc(sizeof(uint64_t));
    *len_vector = 0;

    uint8_t* vector = read_vector(vector_file, len_vector, op_mode, is_encrypt);

    uint8_t* state = vector;
    uint64_t remaining = *len_vector;
    uint64_t block_size = 16;

    uint8_t IV[16];
    uint8_t IV_PREV[16];
    for (int j = 0; j < 16; j++)
        IV[j] = IV_PREV[j] = state[j];

    if (op_mode == CTR)
        for (int j = 0; j < 16; j++)
            IV[j] = IV_PREV[j] = 0;
        
    uint64_t aes_loop_total = *len_vector % 16 == 0 ? *len_vector / 16 : *len_vector / 16 + 1;
    for (uint64_t i = 0; i < aes_loop_total; i++) {
       
        // first block is the IV for non ECB or CTR modes
        if (i == 0) {
            if (op_mode != ECB && op_mode != CTR) {
                remaining -= 16;
                puts("IV used.");
                state += 16;
                continue;
            }
        }
         
        // Copy state bytes to IV, then perform XOR for CFB encryption
        if (!is_encrypt && (op_mode == CBC || op_mode == CFB)) {
            for (int j = 0; j < 16; j++)
                IV[j] = state[j];
        } else if (op_mode == CBC && is_encrypt) {
            puts("CBC encrypt");
            xor_len(state, state-16, 16);
        }

        // Perform encryption/decryption of either the plaintext/ciphertext and key, or the IV with the key
        if (op_mode == ECB || op_mode == CBC)
            aes(state, ekey, len_key, is_encrypt);
        else
            aes(IV_PREV, ekey, len_key, true);

        // Perform post encryption/decryption XORs and IV copying
        if ((op_mode == CBC && !is_encrypt) || (op_mode == CFB && !is_encrypt)) {
            xor_len(state, IV_PREV, block_size);
            for (int j = 0; j < 16; j++)
                IV_PREV[j] = IV[j];
        } else if (op_mode == CFB && is_encrypt) {
            xor_len(state, IV_PREV, block_size);
            for (int j = 0; j < 16; j++)
                IV_PREV[j] = state[j];
        } else if (op_mode == OFB) {
            xor_len(state, IV_PREV, block_size);
        } else if (op_mode == CTR) {
            xor_len(state, IV_PREV, block_size);
            IV[15] ++;
            for (int j = 0; j < 16; j++)
                IV_PREV[j] = IV[j];
        }
        

        // Remove padding 
        if (is_encrypt == false && i == (aes_loop_total - 1) && (op_mode == ECB || op_mode == CBC)) {
            *len_vector -= state[15];
            if ((int)*len_vector < 0) 
                exit(1);
        }
            
        state += 16;
        remaining -= 16;
        
        if (remaining < block_size)
            block_size = remaining;
    }

    free(key);
    free(ekey);
   
    // Print output to a file
    if (op_mode != ECB && op_mode != CTR && !is_encrypt)
        file_output(vector + 16, *len_vector - 16, outfile);
    else
        file_output(vector, *len_vector, outfile);
    
    free(len_vector);
    free(vector);
    
    return 0;
}
