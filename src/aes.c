#include "../include/aes_funcs.h"
#include "../include/expand_key.h"

int main (int argc, char *argv[]) {
    // Parse command line arguments
    if (argc != 4 && argc != 2)
        usage(1); 
    
    if (strcmp(argv[1], "-e") && strcmp(argv[1], "-d")) {
        if (!strcmp(argv[1], "-u") || !strcmp(argv[1], "--useage"))
            usage(0);
        usage(1);
    }

    char* key_file = argv[2];
    char* vector_file = argv[3];

    bool is_encrypt = !strcmp(argv[1], "-e") ? true : false;
     
    uint8_t* key  = malloc(sizeof(uint8_t) * (32 + 1));
    uint8_t* ekey = malloc(sizeof(uint8_t) * (240 + 1));

    int len_key = read_key(key_file, key);

    uint8_t *state = malloc(sizeof(uint8_t) * 16); // state is always 16 bytes

    // TODO: state may always be 16 bytes, but the encryption should work for input of any length
    // TODO: AES should also work for non perfect HEX inputs to encrypt entire files (padding)
    read_vector(vector_file, state);

    // TODO: Loop this
    aes(state, key, len_key, is_encrypt);
    
    for (int i = 0; i < 4; i++)
        printf("%x%x%x%x ", state[i*4], state[i*4+1], state[i*4+2], state[i*4+3]);
    puts("");

    free(key);
    free(ekey);
    free(state);

    return 0;
};
