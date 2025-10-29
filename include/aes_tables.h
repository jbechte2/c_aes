/*
 * -----------------------------------------------------------------------------
 * File: aes_tables.h
 * Author: Jacob Bechtel
 *
 * Description:
 *   Header declarations for AES lookup tables used in key expansion,
 *   SubBytes, InvSubBytes, and MixColumns transformations.
 *   Provides extern references to precomputed constant arrays defined
 *   in aes_tables.c.
 *
 * Attribution:
 *   This header and file was written and formatted with assistance from
 *   OpenAI’s ChatGPT (GPT-5 model) to ensure clarity, consistency,
 *   and compatibility with AES standard specifications.
 *
 * Date: October 2025
 * -----------------------------------------------------------------------------
 */

#ifndef AES_TABLES_H
#define AES_TABLES_H

#include <stdint.h>

/* --------------------------------------------------------------------------
 * AES Substitution Boxes
 * --------------------------------------------------------------------------
 * AES_SBOX:
 *   Forward substitution box used in the SubBytes transformation.
 *
 * AES_INV_SBOX:
 *   Inverse substitution box used in the InvSubBytes transformation.
 * -------------------------------------------------------------------------- */
extern const uint8_t AES_SBOX[256];
extern const uint8_t AES_INV_SBOX[256];

/* --------------------------------------------------------------------------
 * AES Round Constants (Rcon)
 * --------------------------------------------------------------------------
 * Used in the AES key expansion step to generate round keys.
 * Each value corresponds to (x^(i-1)) in GF(2^8).
 * -------------------------------------------------------------------------- */
extern const uint32_t AES_RCON[15];

/* --------------------------------------------------------------------------
 * AES MixColumns Matrices
 * --------------------------------------------------------------------------
 * AES_MUL_E:
 *   Coefficients for the forward MixColumns transformation.
 *
 * AES_MUL_D:
 *   Coefficients for the inverse MixColumns transformation.
 * -------------------------------------------------------------------------- */
extern const uint8_t AES_MUL_E[4][4];
extern const uint8_t AES_MUL_D[4][4];

/* --------------------------------------------------------------------------
 * AES Galois Field Log/Exponent Tables
 * --------------------------------------------------------------------------
 * AES_L:
 *   Log table for finite field GF(2^8) multiplication.
 *
 * AES_E:
 *   Exponent table (anti-log) corresponding to AES_L.
 *   Used to optimize multiplication in MixColumns and InvMixColumns.
 * -------------------------------------------------------------------------- */
extern const uint8_t AES_L[256];
extern const uint8_t AES_E[256];

#endif
