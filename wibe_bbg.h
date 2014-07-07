/**
 * @file WIBE-BBG.h
 * @brief Boneh–Boyen–Goh Wildcarded Identity-Based Encryption Scheme
 *
 * WIBE-BBG is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * WIBE-BBG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with WIBE-BBG.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Oliver Guenther
 * mail@oliverguenther.de
 *
 *
 * wibe_bbg.h
*/

#ifndef H_WIBE_BBG
#define H_WIBE_BBG

#include <string.h>
#include <stdbool.h>
#include <pbc/pbc.h>

/**
  * @typedef Global system parameters
  *
  * Contains the PBC pairing struct
  * and the maximum Pattern hierarchy parameter L
 */
typedef struct bbg_params_s {
	pairing_t pairing;
	unsigned int L;
}* bbg_params_t;

/**
  * @typedef A BBG public key
  *
  * Stores a BBG key
  * (mpk, msk, derived key)
 */
typedef struct bbg_public_key_s {
    element_t g1;
    element_t g2;
    element_t h1;

    /* L+1 u_i elements */
    element_t* u;

}* bbg_public_key_t;

/**
  * @typedef A BBG secret key
  *
  * Stores a BBG master secret/derived key
 */
typedef struct bbg_private_key_s {
    /** Secret key elements */
    element_t* key;
    unsigned int keylen;

    /** ID vector */
    element_t* ID;
    unsigned int l;

}* bbg_private_key_t;


/**
  * @typedef BBG system
  *
  * Stores a master BBG WIBE system
  * (mpk, msk)
 */
typedef struct bbg_system_s {
    bbg_public_key_t mpk;
    bbg_private_key_t msk;
}* bbg_system_t;

/**
 * @typedef A BBG pattern struct
 *
 * Stores a BBG pattern
 */
typedef struct bbg_pattern_s {
    // identities of the pattern
    // (Elements in Zp)
    // Note: This is a sparse array
    // i.e., wildcards are uninitialized elements
    element_t* ids;
    
    // Length of the pattern
    unsigned int len;
    
    // Wildcard locations in the pattern
    bool* wildcards;
    
    
}* bbg_pattern_t;


/**
  * @typedef A BBG ciphertext struct
  *
  * Stores a BBG ciphertext
 */
typedef struct bbg_cipher_s {
    // Pattern this cipher was encrypted under
    bbg_pattern_t pattern;

    // Ciphertexts
    element_t c_1;
    element_t c_2;
    element_t c_3;
    element_t* c_4;
    
}* bbg_cipher_t;

/**
 * @brief Frees a global_params_t
 */
void free_global_params(bbg_params_t gs);

/**
 * @brief Frees a bbg_system_t
 */
void free_system(bbg_system_t sys, bbg_params_t params);

/**
 * @brief Frees a bbg_public_key_t
 */
void free_mpk(bbg_public_key_t mpk, bbg_params_t params);

/**
 * @brief Frees a bbg_private_key_t
 */
void free_sk(bbg_private_key_t key);

/**
 * @brief Frees a bbg_pattern_t
 */
void free_pattern(bbg_pattern_t key);

/**
 * @brief Frees a bbg_cipher_t
 */
void free_cipher(bbg_cipher_t key, bbg_params_t params);


/**
 * Setup global system parameters
 * @param[out] gps bbg_params_t pointer
 * @param[in] params Pairing Type paramters as string
 * @param[in] L Maximum hierarchy depth
 */
void setup_global_system(bbg_params_t* gps, const char* params, unsigned int L);

/**
 * Setup scheme, output bbg master keys (mpk,msk)
 * @param[out] sys bbg_system_t pointer
 * @param[in] gps bbg_params_t
 */
void setup(bbg_system_t* sys, bbg_params_t gps);

/**
 * Output derived key for an identity ID
 * @param[out] key pointer for the identity
 * @param[in] assoc_key key to derive ID with
 * @param[in] mpk The master public key
 * @param[in] id The representation of identity in Z_p
 * @param[in] gps bbg_params_t
 */
void derive_key(bbg_private_key_t* derived_key, bbg_private_key_t secret_key, bbg_public_key_t mpk, element_t id, bbg_params_t params);


/**
 * Encrypt plaintext m as ciphertext ct using master public key and
 * a pattern
 *
 * The input pattern is not copied, but referenced in the cipher
 *
 * @param[out] bbg_cipher_t pointer
 * @param[in] mpk master public key
 * @param[in] pattern array of pattern (string) of length <= L
 * @param[in] m input plaintext (an element of G)
 * @param[in] gps bbg_params_t
 */
 void encrypt(bbg_cipher_t* ct, bbg_public_key_t mpk, bbg_pattern_t p, element_t m, bbg_params_t gps);

/**
 * Decrypt ciphertext into plaintext m
 * @param[out] m pointer to decrypted plaintext
 * @param[in] key secret key for decryption of p
 * @param[in] ct ciphertext struct
 * @param[in] gps bbg_params_t
 */
 void decrypt(element_t m, bbg_private_key_t key, bbg_cipher_t ct, bbg_params_t gps);

#endif
