/*
 * -----------------------------------------------------------------------------
 * File: expand_key.h
 * Author: Jacob Bechtel
 *
 * Description:
 *   Function declarations for AES key expansion and supporting utilities.
 *   Provides routines for reading, parsing, and expanding AES keys into
 *   the full encryption key schedule, as defined by the Rijndael standard.
 *
 * Attribution:
 *   This header and its structured documentation were developed with
 *   assistance from OpenAI’s ChatGPT (GPT-5 model) to maintain consistency,
 *   clarity, and professional formatting across the AES project headers.
 *   All function semantics and implementation details were verified by
 *   the author.
 *
 * Date: October 2025
 * -----------------------------------------------------------------------------
 */

#ifndef EXPAND_KEY_H
#define EXPAND_KEY_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "aes_tables.h"

uint8_t char_to_hex(char c);
void strip_whitespace(char* s);
int read_key(char* key_file, uint8_t* key);
uint32_t rot_word(uint32_t rot_me);
uint32_t sub_word(uint32_t sub_me);
uint32_t rcon(uint32_t rcon_me);
uint32_t EK(uint8_t* ekey, int len_ekey, int offset);
uint32_t K(uint8_t* key, int len_key, int offset);
void store_ekey(uint8_t* loc, uint32_t store_val);
void expand_key(uint8_t* key, int len_key, uint8_t* ekey);

#endif
