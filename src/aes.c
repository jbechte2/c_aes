#include "../include/aes_funcs.h"
#include "../include/expand_key.h"

int main (int argc, char *argv[]) {
    // Delare variables to be assigned by command line arguments
    bool is_encrypt = true;
    Op_mode op_mode = ECB;
    
    // Parse command line arguments
    if (argc < 3)
        usage(1);

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
        } else {
            usage(1);
        }
    }

    // Use encryption mode for decryption for these modes
    //if (op_mode == CFB || op_mode == OFB || op_mode == CTR)
        //is_encrypt = true;
     
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
    printf("len_vector = %ld\n", *len_vector);

    //if (is_encrypt)
        //pad_vector(vector, len_vector, op_mode);
    printf("vector[-1] = %d\n", vector[*len_vector-1]);
    
    //char buffer[*len_vector*BUFSIZ];
    
    //print_uint8_t_array(vector, *len_vector, buffer);
    //printf("%s", buffer);
    
    //printf(" -> ");
    
    uint8_t* state = vector;
    uint64_t remaining = *len_vector;
    uint64_t block_size = 16;

    //for (uint64_t i = 0; i < *len_vector; i++)
        //printf("vector[%ld] = %.2x\n", i, vector[i]);
    
    // TODO: finish implementing non ECB modes
    uint8_t IV[16], IV_PREV[16];
        
    // Copy state bytes to IV 
    if (!is_encrypt && (op_mode == CBC || op_mode == CFB)) {
        for (int j = 0; j < 16; j++)
            IV_PREV[j] = state[j];
    }

    for (uint64_t i = 0; i < *len_vector / 16; i++) {
        printf("remaining = %ld\n", remaining);
       
        // first block is the IV for non ECB CTR modes
        if (i == 0) {
            if (op_mode != ECB && op_mode != CTR) {
                remaining -= 16;
                puts("IV used.");
                state += 16;
            }
            continue;
        }
        
        // Copy state bytes to IV 
        if (!is_encrypt && (op_mode == CBC || op_mode == CFB)) {
            for (int j = 0; j < 16; j++)
                IV[j] = state[j];
        }


        if (is_encrypt)
            for (uint64_t j = 0; j < 16; j++)
                printf("state[%ld] = %.2x\n", j, state[j]);

        if (op_mode == CBC && is_encrypt) {
            puts("CBC encrypt");
            xor_len(state, state-16, 16);
        }

        //printf("aes loop count = %ld\n", i);
        if (op_mode == ECB || op_mode == CBC)
            aes(state, ekey, len_key, is_encrypt);

        if (op_mode == CBC && !is_encrypt) {
            puts("CBC decrypt");
            xor_len(state, IV_PREV, 16);
            for (int j = 0; j < 16; j++)
                IV_PREV[j] = IV[j];

        }

        if (!is_encrypt)
            for (uint64_t j = 0; j < 16; j++)
                printf("state[%ld] = %.2x\n", j, state[j]);
        
        if (i == (*len_vector/16 - 1)) {
            printf("state[15] = %d\n", state[15]);
            printf("vector[-1] = %d\n", vector[*len_vector-1]);
        }
        
        //if (i == (*len_vector/16 - 1))
            //printf("state[15] = %d\n", state[15]);
        
        // TODO: Remove padding function
        if (is_encrypt == false && i == (*len_vector/16 - 1) && (op_mode == ECB || op_mode == CBC)) {
            printf("pad_bytes decrypt = %d\n", state[15]);
            *len_vector -= state[15];
            printf("new len_vector = %ld\n", *len_vector);
            if ((int)*len_vector < 0) {
                fprintf(stderr, "Error decrypting.\n");
                exit(1);
            }
        }
            
        state += 16;
        remaining -= 16;
        
        if (remaining < block_size)
            block_size = remaining;

        
    }

    //print_uint8_t_array(vector, *len_vector, buffer);
    //printf("%s", buffer);

    free(key);
    free(ekey);
    
    if (op_mode != ECB && op_mode != CTR && !is_encrypt)
        file_output(vector + 16, *len_vector - 16, "output");
    else
        file_output(vector, *len_vector, "output");
    
    free(len_vector);
    free(vector);
    
    return 0;
}
