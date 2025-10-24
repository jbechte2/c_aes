#include "../../include/expand_key_test.h"

void test_read_key() {
    char *key_file = "./test_keys/key0";
    uint8_t *key = malloc(sizeof(uint8_t) * (32 + 1));

    assert(read_key(key_file, key) == 16);

    key_file = "./test_keys/key2";
    
    assert(read_key(key_file, key) == 32);
    assert(key[0] == 0x01);

    free(key); 
    puts("read_key passed!");
};

void test_rot_word() {
    assert(rot_word(0x00000000) == 0x00000000);
    assert(rot_word(0x0F0F0F0F) == 0x0F0F0F0F);
    assert(rot_word(0x000000FF) == 0x0000FF00);
    assert(rot_word(0xFF000000) == 0x000000FF);
    puts("rot_word passed!");
};

void test_sub_word() {
    assert(sub_word(0x00000000) == 0x63636363);
    assert(sub_word(0xFF1D4ABC) == 0x16A4D665);
    puts("sub_word passed!");
};

void test_rcon() {
    assert(rcon(0) == 0x01000000);
    assert(rcon(3) == 0x08000000);
    assert(rcon(7) == 0x80000000);
    assert(rcon(14) == 0x9A000000);
    puts("test passed!");
};

void test_EK() {
    uint8_t ekey[176];
    ekey[0] = 0x00;
    ekey[1] = 0x00;
    ekey[2] = 0x00;
    ekey[3] = 0x02;
    ekey[4] = 0xFF;
    ekey[5] = 0x45;
    ekey[6] = 0xAC;
    assert(EK((uint8_t*)&ekey, 176, 0) == 0x00000002);
    assert(EK((uint8_t*)&ekey, 176, 3) == 0x02FF45AC);
    puts("EK passed!");
};

void test_K() {
    uint8_t key[16];
    key[0] = 0x00;
    key[1] = 0x00;
    key[2] = 0x00;
    key[3] = 0x02;
    key[4] = 0xFF;
    key[5] = 0x45;
    key[6] = 0xAC;
    assert(K((uint8_t*)&key, 16, 0) == 0x00000002);
    assert(K((uint8_t*)&key, 16, 3) == 0x02FF45AC);
    puts("K passed!");
};

void test_expand_key() {
    uint8_t* key  = malloc(sizeof(uint8_t) * (32 + 1));
    uint8_t* ekey = malloc(sizeof(uint8_t) * (240 + 1));
    
    char *key_file = "./test_keys/key0";
    expand_key(key, read_key(key_file, key), ekey);

    assert(ekey[0]   == 0x00);
    assert(ekey[1]   == 0x00);
    assert(ekey[2]   == 0x00);
    assert(ekey[16]  == 0x62);
    assert(ekey[75]  == 0xb2);

    key_file = "./test_keys/key024";
    
    expand_key(key, read_key(key_file, key), ekey);
    
    assert(ekey[0]   == 0x00);
    assert(ekey[1]   == 0x00);
    assert(ekey[2]   == 0x00);
    assert(ekey[24]  == 0x62);

    key_file = "./test_keys/key032";
    expand_key(key, read_key(key_file, key), ekey);
    
    assert(ekey[0]   == 0x00);
    assert(ekey[1]   == 0x00);
    assert(ekey[2]   == 0x00);
    assert(ekey[32]  == 0x62);
    assert(ekey[239] == 0x85);

    free(key);
    free(ekey);
}

void test_all_expand_key() {
    test_read_key();
    test_rot_word();
    test_sub_word();
    test_rcon();
    test_EK();
    test_K();
    test_expand_key();
    puts("All expand_key tests passed!");
};
