/**
 * @file testscheme.c
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
#include "wibe_bbg.h"


int main(int argc, const char *argv[]) {

    FILE *param = fopen("/Users/oliver/mydev/BBG-WIBE/a.param", "r");
    char buf[4096];
    fread(buf, 1, 4096, param);

    printf("== System setup ==\n");

    // Initialize global parameter
    bbg_params_t params;
    setup_global_system(&params, (const char*) buf, 2);

    // Initialize WIBE system
    bbg_system_t sys;
    setup(&sys, params);

    printf("System is set up\n\n=== Master Public Key ===\n");
    element_printf("g_1: %B\n", sys->mpk->g1);
    element_printf("g_2: %B\n", sys->mpk->g2);
    element_printf("h_1: %B\n", sys->mpk->h1);

    for(int i = 0; i <= params->L; i++) {
        element_printf("u_%d: %B\n", i, sys->mpk->u[i]);
    }

    printf("\n=== Master Secret Key ===\n");
    for(int i = 0; i < sys->msk->keylen; i++) {
        element_printf("d_%d: %B\n", i, sys->msk->key[i]);
    }
    
    printf("=== Deriving identities ===\n");
    
    int users = 4;

    /** Three identities in Zr */
    element_t* ids;
    /** Three derived keys of msk */
    bbg_private_key_t* subkeys;
    /** Three 0 decryptions keys derived by subkey[i] */
    bbg_private_key_t* sub_deckey;
    ids = pbc_malloc(users * sizeof(element_t));
    subkeys = pbc_malloc(users * sizeof(bbg_private_key_t));
    sub_deckey = pbc_malloc(users * sizeof(bbg_private_key_t));

    // Every user derives their own key with id=0
    element_t own_id;
    element_init_Zr(own_id, params->pairing);
    element_set0(own_id);

    // Derive sub-keys
    for (int i = 0; i < users; i++) {
        element_init_Zr(ids[i], params->pairing);
        element_set_si(ids[i], i);
        
        printf("[id=%i] ", (i+1));
        derive_key(&subkeys[i], sys->msk, sys->mpk, ids[i], params);
        derive_key(&sub_deckey[i], subkeys[i], sys->mpk, own_id, params);
    }
    
    element_t m;
    element_init_GT(m, params->pairing);
    element_random(m);
    
    // Pattern 1: [i,0]
    bbg_pattern_t p;
    p = pbc_malloc(sizeof(struct bbg_pattern_s));
    p->len = 2;
    p->wildcards = malloc(2 * sizeof(bool));
    p->wildcards[0] = false;
    p->wildcards[1] = false;
    p->ids = pbc_malloc(2 * sizeof(element_t));
    element_init_Zr(p->ids[0], params->pairing);
    element_init_Zr(p->ids[1], params->pairing);
    element_set(p->ids[1], own_id);

    bbg_cipher_t ct;
    element_t dec;
    element_init_GT(dec, params->pairing);

    int nErrors = 0;
    printf("\n === Testing Patterns === \n");
    for (int i = 0; i < users; ++i) {
        element_set(p->ids[0], ids[i]);
        printf("[%d,0] ", i);
        encrypt(&ct, sys->mpk, p, m, params);
        for (int j = 0; j < users; ++j) {
            decrypt(dec, sub_deckey[j], ct, params);

            if (j == i) {
                if (element_cmp(m, dec) != 0) {
                    element_printf("user %d: Decryption failed\n", j);
                    nErrors++;
                }

            } else if (element_cmp(m, dec) == 0) {
                element_printf("user %i: Decrypt should have failed\n", i+1);
                nErrors++;
            }
        }

    }



    // Pattern 3: [*,0]
    printf("[*,0]");
    p->wildcards[0] = true;
    element_clear(p->ids[0]);
    encrypt(&ct, sys->mpk, p, m, params);

    for (int i = 0; i < users; ++i) {
        decrypt(dec, sub_deckey[i], ct, params);
        if (element_cmp(m, dec) != 0) {
            element_printf("\nuser %i: Decrypt failed\n", i+1);
            nErrors++;
        }
    }

    // Pattern 4: [*,*]
    printf(" [*,*]");
    p->wildcards[0] = true;
    p->wildcards[1] = true;
    element_clear(p->ids[1]);
    encrypt(&ct, sys->mpk, p, m, params);

    for (int i = 0; i < users; ++i) {
        decrypt(dec, sub_deckey[i], ct, params);
        if (element_cmp(m, dec) != 0) {
            element_printf("\nuser %i: Decrypt failed\n", i+1);
            nErrors++;
        }
    }

    if (nErrors > 0) {
        printf("\n\n%d pattern tests were erroneous. Please validate PBC, GMP installation.", nErrors);
    } else {
        printf("\n\n... All tests successful.\n");
    }

    return nErrors;
}
