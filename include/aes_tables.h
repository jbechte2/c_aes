#ifndef AES_TABLES_H
#define AES_TABLES_H

#include <stdint.h>

// Forward/Inverse SubBytes
extern const uint8_t AES_SBOX[256];
extern const uint8_t AES_INV_SBOX[256];

// Rcon for key expansion
extern const uint32_t AES_RCON[15];

// MixColumns matricies
extern const uint8_t AES_MUL_E[4][4];
extern const uint8_t AES_MUL_D[4][4];

extern const uint8_t AES_L[256];
extern const uint8_t AES_E[256];

#endif

