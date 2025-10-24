#ifndef AES_TEST_H
#define AES_TEST_H

#include <assert.h>
#include "aes_funcs.h"

void test_read_vector();
void test_add_round_key();
void test_byte_sub();
void test_shift_row();
void test_gf_mul();
void test_mix_column();
void test_all_aes();

#endif
