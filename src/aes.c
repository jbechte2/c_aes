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

    char* key_file = argv[argc - 2];
    char* vector_file = argv[argc - 1];

     
    uint8_t* key  = malloc(sizeof(uint8_t) * (32 + 1));

    int len_key = read_key(key_file, key);

    uint8_t* ekey = malloc(sizeof(uint8_t) * 240);
    expand_key(key, len_key, ekey);

    uint64_t *len_vector = malloc(sizeof(uint64_t));
    *len_vector = 0;

    uint8_t* vector = read_vector(vector_file, len_vector, is_encrypt);
    //printf("len_vector = %ld\n", *len_vector);
    
    //char buffer[*len_vector*BUFSIZ];
    
    //print_uint8_t_array(vector, len_vector, buffer);
    //printf("%s", buffer);
    
    //printf(" -> ");
    
    uint8_t* state = vector;
    //for (uint64_t i = 0; i < *len_vector; i++)
        //printf("vector[%ld] = %.2x\n", i, vector[i]);
    
    // TODO: finish implementing non ECB modes

    // Use encryption mode for decryption for these modes
    if (op_mode == CFB || op_mode == OFB || op_mode == CTR)
        is_encrypt = true;
     
    for (uint64_t i = 0; i < *len_vector / 16; i++) {
        //printf("aes loop count = %ld\n", i);
        aes(state, ekey, len_key, is_encrypt);
        state += 16;
    }

    //print_uint8_t_array(vector, *len_vector, buffer);
    //printf("%s", buffer);

    free(len_vector);
    free(key);
    free(ekey);
    free(vector);
    
    return 0;
}
