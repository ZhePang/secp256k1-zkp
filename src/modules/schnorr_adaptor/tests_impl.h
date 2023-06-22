/**********************************************************************
 * Copyright (c) 2023 Zhe Pang                                        *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_SCHNORR_ADAPTOR_TESTS_H
#define _SECP256K1_MODULE_SCHNORR_ADAPTOR_TESTS_H

#include "../../../include/secp256k1_schnorr_adaptor.h"

/* Checks that a bit flip in the n_flip-th argument (that has n_bytes many
 * bytes) changes the hash function
 */
void nonce_function_bip340_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes, size_t algolen) {
    unsigned char nonces[2][32];
    CHECK(nonce_function_bip340(nonces[0], args[0], args[1], args[2], args[3], args[4], algolen, args[5]) == 1);
    secp256k1_testrand_flip(args[n_flip], n_bytes);
    CHECK(nonce_function_bip340(nonces[1], args[0], args[1], args[2], args[3], args[4], algolen, args[5]) == 1);
    CHECK(secp256k1_memcmp_var(nonces[0], nonces[1], 32) != 0);
}

/* Tests for the equality of two sha256 structs. This function only produces a
 * correct result if an integer multiple of 64 many bytes have been written
 * into the hash functions. */
void test_sha256_eq(const secp256k1_sha256 *sha1, const secp256k1_sha256 *sha2) {
    /* Is buffer fully consumed? */
    CHECK((sha1->bytes & 0x3F) == 0);

    CHECK(sha1->bytes == sha2->bytes);
    CHECK(secp256k1_memcmp_var(sha1->s, sha2->s, sizeof(sha1->s)) == 0);
}

void run_nonce_function_bip340_tests(void) {
    unsigned char tag[13] = "BIP0340/nonce";
    unsigned char aux_tag[11] = "BIP0340/aux";
    unsigned char algo[13] = "BIP0340/nonce";
    size_t algolen = sizeof(algo);
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;
    unsigned char nonce[32], nonce_z[32];
    unsigned char msg[32];
    unsigned char key[32];
    unsigned char t[32];
    unsigned char pk[32];
    unsigned char aux_rand[32];
    unsigned char *args[6];
    int i;

    /* Check that hash initialized by
     * secp256k1_nonce_function_bip340_sha256_tagged has the expected
     * state. */
    secp256k1_sha256_initialize_tagged(&sha, tag, sizeof(tag));
    secp256k1_nonce_function_bip340_sha256_tagged(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

   /* Check that hash initialized by
    * secp256k1_nonce_function_bip340_sha256_tagged_aux has the expected
    * state. */
    secp256k1_sha256_initialize_tagged(&sha, aux_tag, sizeof(aux_tag));
    secp256k1_nonce_function_bip340_sha256_tagged_aux(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

    secp256k1_testrand256(msg);
    secp256k1_testrand256(key);
    secp256k1_testrand256(t);
    secp256k1_testrand256(pk);
    secp256k1_testrand256(aux_rand);

    /* Check that a bitflip in an argument results in different nonces. */
    args[0] = msg;
    args[1] = key;
    args[2] = t;
    args[3] = pk;
    args[4] = algo;
    args[5] = aux_rand;
    for (i = 0; i < count; i++) {
        nonce_function_bip340_bitflip(args, 0, 32, algolen);
        nonce_function_bip340_bitflip(args, 1, 32, algolen);
        nonce_function_bip340_bitflip(args, 2, 32, algolen);
        nonce_function_bip340_bitflip(args, 3, 32, algolen);
        /* Flip algo special case "BIP0340/nonce" */
        nonce_function_bip340_bitflip(args, 4, algolen, algolen);
        /* Flip algo again */
        nonce_function_bip340_bitflip(args, 4, algolen, algolen);
        nonce_function_bip340_bitflip(args, 5, 32, algolen);
    }

    /* NULL algo is disallowed */
    CHECK(nonce_function_bip340(nonce, msg, key, t, pk, NULL, 0, NULL) == 0);
    CHECK(nonce_function_bip340(nonce, msg, key, t, pk, algo, algolen, NULL) == 1);
    /* Other algo is fine */
    secp256k1_testrand_bytes_test(algo, algolen);
    CHECK(nonce_function_bip340(nonce, msg, key, t, pk, algo, algolen, NULL) == 1);

    for (i = 0; i < count; i++) {
        unsigned char nonce2[32];
        size_t algolen_tmp;

        /* Different algolen gives different nonce */
        uint32_t offset = secp256k1_testrand_int(algolen - 1);
        algolen_tmp = (algolen + offset) % algolen;
        CHECK(nonce_function_bip340(nonce2, msg, key, t, pk, algo, algolen_tmp, NULL) == 1);
        CHECK(secp256k1_memcmp_var(nonce, nonce2, 32) != 0);
    }

    /* NULL aux_rand argument is allowed, and identical to passing all zero aux_rand. */
    memset(aux_rand, 0, 32);
    CHECK(nonce_function_bip340(nonce_z, msg, key, t, pk, algo, algolen, &aux_rand) == 1);
    CHECK(nonce_function_bip340(nonce, msg, key, t, pk, algo, algolen, NULL) == 1);
    CHECK(secp256k1_memcmp_var(nonce_z, nonce, 32) == 0);
}

void run_schnorr_adaptor_tests(void) {
    int i;
    run_nonce_function_bip340_tests();
}

#endif
