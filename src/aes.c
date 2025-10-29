#include "../include/aes_funcs.h"
#include "../include/expand_key.h"

int main (int argc, char *argv[]) {
    // Parse command line arguments
    if (argc != 4 && argc != 2)
        usage(1); 
    
    if (strcmp(argv[1], "-e") && strcmp(argv[1], "-d")) {
        if (!strcmp(argv[1], "-u") || !strcmp(argv[1], "--usage"))
            usage(0);
        usage(1);
    }

    char* key_file = argv[2];
    char* vector_file = argv[3];

    bool is_encrypt = !strcmp(argv[1], "-e") ? true : false;
     
    uint8_t* key  = malloc(sizeof(uint8_t) * (32 + 1));
    uint8_t* ekey = malloc(sizeof(uint8_t) * (240 + 1));

    int len_key = read_key(key_file, key);

    uint64_t *len_vector = malloc(sizeof(uint64_t));
    *len_vector = 0;

    uint8_t* vector = read_vector(vector_file, len_vector);
    printf("len_vector = %ld\n", *len_vector);
    
    //char buffer[*len_vector*BUFSIZ];
    
    //print_uint8_t_array(vector, len_vector, buffer);
    //printf("%s", buffer);
    
    //printf(" -> ");
    
    uint8_t* state = vector;
    //for (uint64_t i = 0; i < *len_vector; i++)
        //printf("vector[%ld] = %.2x\n", i, vector[i]);
    
    for (uint64_t i = 0; i < *len_vector / 16; i++) {
        //printf("aes loop count = %ld\n", i);
        aes(state, key, len_key, is_encrypt);
        state += 16;
    }

    //print_uint8_t_array(vector, *len_vector, buffer);
    //printf("%s", buffer);

    free(len_vector);
    free(key);
    free(ekey);
    free(vector);

    return 0;
};
