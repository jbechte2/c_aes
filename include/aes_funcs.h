#ifndef AES_FUNCS_H
#define AES_FUNCS_H

#include <stdbool.h>
#include <time.h>
#include "expand_key.h"

typedef enum op_mode {
    ECB, CBC, CFB, OFB, CTR
} Op_mode;

void usage(int exit_code);
uint8_t* gen_IV();
uint8_t* read_vector(char* vector_file, uint64_t* size, Op_mode op_mode, bool is_encrypt);
void pad_vector(uint8_t* vector, uint64_t* size, Op_mode op_mode);
void xor_len(uint8_t* v1, uint8_t* v2, uint64_t length);
void add_round_key(uint8_t* state, uint8_t* ekey, int offset);
void byte_sub(uint8_t* state, bool is_encrypt);
void shift_row(uint8_t* state, bool is_encrypt);
uint8_t gf_mul(uint8_t a, uint8_t b);
void mix_column(uint8_t* state, bool is_encrypt);
void aes(uint8_t* state, uint8_t* ekey, int len_key, bool is_encrypt);
void print_uint8_t_array(uint8_t* arr, int len_arr, char* result);
void file_output(uint8_t* vector, uint64_t len_vector, const char* outfile);

#endif
