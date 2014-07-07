/*
 * WIBE-BBG
 * Boneh–Boyen–Goh Wildcarded Identity-Based Encryption Scheme
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
 * wibe_bbg.c
 */


#include <string.h>
#include <stdio.h>
#include <math.h>

#include "wibe_bbg.h"

void setup_global_system(bbg_params_t* gps, const char* pairing_str, unsigned int l) {
    // init global params
    bbg_params_t params;
    params = pbc_malloc(sizeof(struct bbg_params_s));
    
    // Set hierarchy depth
    params->L = l;
    
    // Init pairing
    pairing_init_set_str(params->pairing, pairing_str);
    
    *gps = params;
}

void setup(bbg_system_t* sys_p, bbg_params_t params) {
    
    // Init system
    bbg_system_t gbs;
    gbs = pbc_malloc(sizeof(struct bbg_system_s));


    // Initialize mpk
    // mpk = (g_1, g_2, h_1, u_0, .. , u_L)
    gbs->mpk = pbc_malloc(sizeof(struct bbg_public_key_s));


    // Choose random g_1, g_2 from G
    element_init_G1(gbs->mpk->g1, params->pairing);
    element_random(gbs->mpk->g1);
    element_init_G1(gbs->mpk->g2, params->pairing);
    element_random(gbs->mpk->g2);
    
    // Choose random alpha from Zp
    element_t alpha;
    element_init_Zr(alpha, params->pairing);
    element_random(alpha);

    // Compute h_1 as g_1^(alpha)
    element_init_G1(gbs->mpk->h1, params->pairing);
    element_pow_zn(gbs->mpk->h1, gbs->mpk->g1, alpha);

    // Choose random u_i for i = 0, .. , L
    gbs->mpk->u = pbc_malloc( (params->L + 1) * sizeof(element_t));
    for(int i = 0; i <= params->L; i++) {
        element_init_G1(gbs->mpk->u[i], params->pairing);
        element_random(gbs->mpk->u[i]);
    }

    // Initialize msk
    gbs->msk = pbc_malloc(sizeof(struct bbg_private_key_s));
    // mpk = (d_0, d_1, ..., d_L, d_L+1)
    gbs->msk->keylen = params->L + 2;
    gbs->msk->key = pbc_malloc(gbs->msk->keylen * sizeof(element_t));
    
    // Set d_0 to g_2 ^ alpha
    element_init_G1(gbs->msk->key[0], params->pairing);
    element_pow_zn(gbs->msk->key[0], gbs->mpk->g2, alpha);
    element_clear(alpha);

    // Initialize all elements of msk as 1 in G
    for(int i = 1; i < gbs->msk->keylen; i++) {
        element_init_G1(gbs->msk->key[i], params->pairing);
        element_set1(gbs->msk->key[i]);
    }

    // For MSK, ID is an empty vector
    gbs->msk->l = 0;
    
    *sys_p = gbs;
    
}

void derive_key(bbg_private_key_t* derived_key, bbg_private_key_t secret_key,
                bbg_public_key_t mpk, element_t id, bbg_params_t params) {
    
    // Initialize derived_key
    bbg_private_key_t derived;
    derived = pbc_malloc(sizeof(struct bbg_private_key_s));
    
    // Length of secret_key = l (0 <= l <= L)
    // secret key = (d_0, d_l+1, ..., d_L, d_L+1)
    // new key   = (d_0', d_l+2', ...,  d_L, d_L+1)
    derived->keylen = secret_key->keylen - 1;
    derived->key = pbc_malloc(derived->keylen * sizeof(element_t));

    // Length of ID
    derived->l = secret_key->l + 1;
    derived->ID = pbc_malloc(derived->l * sizeof(element_t));

    // Copy IDs
    for(int i = 0; i < secret_key->l; i++) {
        element_init_Zr(derived->ID[i], params->pairing);
        element_set(derived->ID[i], secret_key->ID[i]);
    }
    // Add latest ID
    element_init_Zr(derived->ID[derived->l - 1], params->pairing);
    element_set(derived->ID[derived->l - 1], id);

    // Initialize all elements of the derived key in G
    for(int i = 0; i < derived->keylen; i++) {
        element_init_G1(derived->key[i], params->pairing);
    }


    // Initialize r as random from Zp
    element_t r;
    element_init_Zr(r, params->pairing);
    element_random(r);

    element_t temp;
    element_init_G1(temp, params->pairing);

    // Compute d_0'
    element_set(derived->key[0], mpk->u[0]);
    for(int i = 0; i < derived->l; i++) {
        // pow u_(i+1) with ID
        element_pow_zn(temp, mpk->u[i+1], derived->ID[i]);
        element_mul(derived->key[0], derived->key[0], temp);
    }


    // Lastly pow with r
    element_pow_zn(derived->key[0], derived->key[0], r);
    
    // compute d_l+1 ^ ID_l+1
    element_set(temp, secret_key->key[1]);
    element_pow_zn(temp, temp, id);
    
    // Multiply with temp
    element_mul(derived->key[0], derived->key[0], temp);
    
    // Multiply with d_0
    element_mul(derived->key[0], derived->key[0], secret_key->key[0]);

    // Compute d_i's of derived key
    for (int i = 2; i < secret_key->keylen - 1; i++) {
        element_pow_zn(derived->key[i - 1], mpk->u[(secret_key->l + i)], r);
        element_mul(derived->key[i - 1], derived->key[i - 1], secret_key->key[i]);
    }

    // Finally, compute d_L+1' as (g_1 ^ r) * d_L+1
    int last_pos = derived->keylen - 1;
    element_pow_zn(derived->key[last_pos], mpk->g1, r);
    element_mul(derived->key[last_pos], derived->key[last_pos], secret_key->key[last_pos + 1]);
    
    // Free temporary helpers
    element_clear(r);
    element_clear(temp);
    
    *derived_key = derived;
}


void encrypt(bbg_cipher_t* ct, bbg_public_key_t mpk, bbg_pattern_t p,
             element_t m, bbg_params_t params) {
    
    bbg_cipher_t cipher;
    cipher = pbc_malloc(sizeof(struct bbg_cipher_s));
    
    // reference pattern in c
    cipher->pattern = p;
    
    // Initialize r
    element_t r;
    element_init_Zr(r, params->pairing);
    element_random(r);
    
    // Initialize c_1 as g_1 ^ r
    element_init_G1(cipher->c_1, params->pairing);
    element_pow_zn(cipher->c_1, mpk->g1, r);
    
    // Compute c_2 and c_4
    element_init_G1(cipher->c_2, params->pairing);
    // c_4 is a vector of length |P|
    cipher->c_4 = pbc_malloc(p->len * sizeof(element_t));
    
    element_set(cipher->c_2, mpk->u[0]);
    
    element_t temp;
    element_init_G1(temp, params->pairing);
    
    for (int i = 0; i < p->len; i++) {
        if (p->wildcards[i]) {
            // Set c_4[i] to u_i ^ r
            element_init_G1(cipher->c_4[i], params->pairing);
            element_set(cipher->c_4[i], mpk->u[i+1]);
            element_pow_zn(cipher->c_4[i], cipher->c_4[i], r);
        } else {
            // Multiply u_i for each position in pattern p
            // that is not a wildcard
            element_pow_zn(temp, mpk->u[i+1], p->ids[i]);
            element_mul(cipher->c_2, cipher->c_2, temp);
        }
    }

    // Finalize c_2 as c_2 ^ r
    element_pow_zn(cipher->c_2, cipher->c_2, r);
    
    // Compute c_3 as m * e(h1, g2)^3
    element_init_GT(cipher->c_3, params->pairing);
    element_pairing(cipher->c_3, mpk->h1, mpk->g2);
    element_pow_zn(cipher->c_3, cipher->c_3, r);
    element_mul(cipher->c_3, cipher->c_3, m);
    
    element_clear(temp);
    element_clear(r);
    
    *ct = cipher;
}

void decrypt(element_t m, bbg_private_key_t sk, bbg_cipher_t ct, bbg_params_t params) {
    
    // Compute c_2'
    element_t c_2n, temp;
    element_init_G1(c_2n, params->pairing);
    element_init_G1(temp, params->pairing);
    // Initialize c_2' as c_2
    element_set(c_2n, ct->c_2);
    
    for (int i = 0; i < ct->pattern->len; i++) {
        if (ct->pattern->wildcards[i]) {
            // Compute v_i ^ ID_i for each i in p that is a wildcard
            element_pow_zn(temp, ct->c_4[i], sk->ID[i]);
            element_mul(c_2n, c_2n, temp);
            
        }
    }
    
    // Compute m as c_3 * e(c_2', d_L+1) / e(c_1, d_0)
    
    element_clear(temp);
    element_init_GT(temp, params->pairing);
    element_init_GT(m, params->pairing);
    element_pairing(m, c_2n, sk->key[sk->keylen - 1]);
    element_pairing(temp, ct->c_1, sk->key[0]);
    element_div(m, m, temp);
    element_mul(m, m, ct->c_3);
        
    element_clear(temp);
    
}


void free_global_params(bbg_params_t gs) {
    if (!gs) return;
    pairing_clear(gs->pairing);
    free(gs);
}

void free_sk(bbg_private_key_t k) {
    if (!k) return;


    for (int i = 0; i < k->l; i++) {
        element_clear(k->ID[i]);
    }
    
    for (int i = 0; i < k->keylen; i++) {
        element_clear(k->key[i]);
    }
    
    free(k);
}

void free_mpk(bbg_public_key_t mpk, bbg_params_t params) {
    if (!mpk) return;


    element_clear(mpk->g1);
    element_clear(mpk->g2);
    element_clear(mpk->h1);

    for (int i = 0; i <= params->L; i++) {
        element_clear(mpk->u[i]);
    }
    
    free(mpk);
}



void free_system(bbg_system_t sys, bbg_params_t params) {
    if (!sys) return;
    
    free_mpk(sys->mpk, params);
    free_sk(sys->msk);
    free(sys);
}

void free_pattern(bbg_pattern_t p) {
    if (!p) return;
    
    for (int i = 0; i < p->len; i++) {
        // Ignore if wildcard
        if(p->wildcards[i]) continue;
        
        // Otherwise, clear the ID
        element_clear(p->ids[i]);
    }
    free(p->ids);
    free(p->wildcards);
    free(p);
}

void free_cipher(bbg_cipher_t ct, bbg_params_t params) {
    if(!ct) return;
    
    // Free ciphertext elements
    element_clear(ct->c_1);
    element_clear(ct->c_2);
    element_clear(ct->c_3);
    for (int i = 0; i < ct->pattern->len; i++) {
        if (ct->pattern->wildcards[i])
            element_clear(ct->c_4[i]);
    }
    
    
    free_pattern(ct->pattern);
    free(ct);
}
