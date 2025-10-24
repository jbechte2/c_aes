#include "../../include/aes_test.h"

void test_read_vector() {
    puts("read_vector passed! (DUH)"); 
}

void test_add_round_key() {
    char* vector_file = "test_vectors/vector0";
    char* key_file = "test_keys/key0";
    uint8_t* state = malloc(sizeof(uint8_t) * (16 + 1));
    uint8_t* key   = malloc(sizeof(uint8_t) * (32 + 1));
    uint8_t* ekey  = malloc(sizeof(uint8_t) * (240 + 1));
    
    read_vector(vector_file, state);

    int len_key = read_key(key_file, key);
    
    expand_key(key, len_key, ekey);

    add_round_key(state, ekey, 1);

    assert(state[0] == 0x62); 
    assert(state[15] == 0x1c); 

    free(state);
    free(key);
    free(ekey);
    
    puts("add_round_key passed!"); 
}

void test_byte_sub() {
    char* vector_file = "test_vectors/vector0";
    char* key_file = "test_keys/key0";
    uint8_t* state = malloc(sizeof(uint8_t) * (16 + 1));
    uint8_t* key   = malloc(sizeof(uint8_t) * (32 + 1));
    uint8_t* ekey  = malloc(sizeof(uint8_t) * (240 + 1));
    
    read_vector(vector_file, state);

    int len_key = read_key(key_file, key);
    
    expand_key(key, len_key, ekey);

    byte_sub(state, true);

    assert(state[0] == 0x63);
    assert(state[15] == 0xd2);

    free(state);
    free(key);
    free(ekey);
    
    puts("byte_sub passed!"); 
}

void test_shift_row() {
    char* vector_file = "test_vectors/vector0";
    char* key_file = "test_keys/key0";
    uint8_t* state = malloc(sizeof(uint8_t) * (16 + 1));
    uint8_t* key   = malloc(sizeof(uint8_t) * (32 + 1));
    uint8_t* ekey  = malloc(sizeof(uint8_t) * (240 + 1));
    
    read_vector(vector_file, state);

    int len_key = read_key(key_file, key);
    
    expand_key(key, len_key, ekey);

    shift_row(state, true);

    assert(state[0] == 0x00);
    assert(state[5] == 0x0f);
    assert(state[15] == 0x1f);

    free(state);
    free(key);
    free(ekey);

    puts("shift_row passed!"); 
}
void test_gf_mul() {
    assert(gf_mul(0x00, 0x00) == 0);
    assert(gf_mul(0x22, 0x00) == 0);
    assert(gf_mul(0x01, 0x22) == 0x22);
    assert(gf_mul(0x55, 0x01) == 0x55);
    assert(gf_mul(0xAF, 0x08) == 0x0F);

    puts("gf_mul passed!");
}

void test_mix_column() {
    uint8_t* state = malloc(sizeof(uint8_t) * (16 + 1));
    state[0] = 0xD4;
    state[1] = 0xBF;
    state[2] = 0x5D;
    state[3] = 0x30; 

    state[4] = 0xD4;
    state[5] = 0xBF;
    state[6] = 0x5D;
    state[7] = 0x30;

    state[8] = 0xD4;
    state[9] = 0xBF;
    state[10] = 0x5D;
    state[11] = 0x30;

    state[12] = 0xD4;
    state[13] = 0xBF;
    state[14] = 0x5D;
    state[15] = 0x30;

    mix_column(state, true);
    assert(state[0] == 0x04);
    assert(state[1] == 0x66);
    assert(state[2] == 0x81);
    assert(state[3] == 0xE5);

    assert(state[4] == 0x04);
    assert(state[5] == 0x66);
    assert(state[6] == 0x81);
    assert(state[7] == 0xE5);

    assert(state[8] == 0x04);
    assert(state[9] == 0x66);
    assert(state[10] == 0x81);
    assert(state[11] == 0xE5);

    assert(state[12] == 0x04);
    assert(state[13] == 0x66);
    assert(state[14] == 0x81);
    assert(state[15] == 0xE5);

    mix_column(state, false);
    assert(state[0] == 0xD4);
    assert(state[1] == 0xBF);
    assert(state[2] == 0x5D);
    assert(state[3] == 0x30);

    assert(state[4] == 0xD4);
    assert(state[5] == 0xBF);
    assert(state[6] == 0x5D);
    assert(state[7] == 0x30);

    assert(state[8] == 0xD4);
    assert(state[9] == 0xBF);
    assert(state[10] == 0x5D);
    assert(state[11] == 0x30);

    assert(state[12] == 0xD4);
    assert(state[13] == 0xBF);
    assert(state[14] == 0x5D);
    assert(state[15] == 0x30);

    free(state);
    puts("mix_columns passed!");
}

void test_aes() {
    uint8_t* key  = malloc(sizeof(uint8_t) * (32 + 1));

    char* key_file = "test_keys/key0";
    char* vector_file = "test_vectors/vector0";

    int len_key = read_key(key_file, key);

    uint8_t *state = malloc(sizeof(uint8_t) * 16);
    uint8_t *vector = malloc(sizeof(uint8_t) * 16);

    read_vector(vector_file, state);

    for (int i = 0; i < 16; i++)
        vector[i] = state[i];


    aes(state, key, len_key, true);

    assert(state[0] == 0xC7);
    assert(state[1] == 0xD1);
    assert(state[2] == 0x24);
    assert(state[3] == 0x19);
    
    assert(state[4] == 0x48);
    assert(state[5] == 0x9E);
    assert(state[6] == 0x3B);
    assert(state[7] == 0x62);
    
    assert(state[8] == 0x33);
    assert(state[9] == 0xA2);
    assert(state[10] == 0xC5);
    assert(state[11] == 0xA7);
    
    assert(state[12] == 0xF4);
    assert(state[13] == 0x56);
    assert(state[14] == 0x31);
    assert(state[15] == 0x72);

    aes(state, key, len_key, false);

    for (int i = 0; i < 16; i++)
        assert(state[i] == vector[i]);
    
    char buffer[BUFSIZ];
    print_uint8_t_array(state, 16, buffer);
    printf("%s\n", buffer);

    free(key);
    free(state);
    free(vector);
    puts("aes passed!");
}

void test_all_aes() {
    test_read_vector();
    test_add_round_key();
    test_gf_mul();
    test_mix_column();
    test_aes();
    puts("All aes tests passed!");
};
