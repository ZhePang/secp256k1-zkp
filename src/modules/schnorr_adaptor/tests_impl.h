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

void test_schnorr_adaptor_api(void) {
    unsigned char sk1[32];
    unsigned char sk2[32];
    unsigned char sk3[32];
    unsigned char msg[32];
    unsigned char t[33] = {
        0x02, 0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D,
        0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0, 0x7C,
        0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C,
        0xA7, 0xAB, 0xAC, 0x09, 0xB9, 0x5C, 0x70, 0x9E, 0xE5
    };
    secp256k1_keypair keypairs[3];
    secp256k1_keypair invalid_keypair = {{ 0 }};
    secp256k1_xonly_pubkey pk[3];
    secp256k1_xonly_pubkey zero_pk;
    unsigned char sig[65];

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *sttc = secp256k1_context_clone(secp256k1_context_no_precomp);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sttc, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sttc, counting_illegal_callback_fn, &ecount);

    secp256k1_testrand256(sk1);
    secp256k1_testrand256(sk2);
    secp256k1_testrand256(sk3);
    secp256k1_testrand256(msg);
    CHECK(secp256k1_keypair_create(ctx, &keypairs[0], sk1) == 1);
    CHECK(secp256k1_keypair_create(ctx, &keypairs[1], sk2) == 1);
    CHECK(secp256k1_keypair_create(ctx, &keypairs[2], sk3) == 1);
    CHECK(secp256k1_keypair_xonly_pub(ctx, &pk[0], NULL, &keypairs[0]) == 1);
    CHECK(secp256k1_keypair_xonly_pub(ctx, &pk[1], NULL, &keypairs[1]) == 1);
    CHECK(secp256k1_keypair_xonly_pub(ctx, &pk[2], NULL, &keypairs[2]) == 1);
    memset(&zero_pk, 0, sizeof(zero_pk));

    /** main test body **/
    ecount = 0;
    CHECK(secp256k1_schnorr_adaptor_presign(none, sig, msg, &keypairs[0], t, NULL) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_schnorr_adaptor_presign(vrfy, sig, msg, &keypairs[0], t, NULL) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_schnorr_adaptor_presign(sign, sig, msg, &keypairs[0], t, NULL) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_schnorr_adaptor_presign(sign, NULL, msg, &keypairs[0], t, NULL) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_schnorr_adaptor_presign(sign, sig, NULL, &keypairs[0], t, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_schnorr_adaptor_presign(sign, sig, msg, NULL, t, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_schnorr_adaptor_presign(sign, sig, msg, &keypairs[0], NULL, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_schnorr_adaptor_presign(sign, sig, msg, &invalid_keypair, t, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_schnorr_adaptor_presign(sttc, sig, msg, &keypairs[0], t, NULL) == 0);
    CHECK(ecount == 6);

    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
    secp256k1_context_destroy(sttc);
}

/* Checks that hash initialized by secp256k1_schnorrsig_sha256_tagged has the
 * expected state. */
void test_schnorrsig_sha256_tagged(void) {
    unsigned char tag[17] = "BIP0340/challenge";
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;

    secp256k1_sha256_initialize_tagged(&sha, (unsigned char *) tag, sizeof(tag));
    secp256k1_schnorrsig_sha256_tagged(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);
}

/* Helper function for schnorr_adaptor_vectors
 * Signs the message and checks that it's the same as expected_sig. */
void test_schnorr_adaptor_vectors_check_presigning(const unsigned char *sk, const unsigned char *pk_serialized, const unsigned char *aux_rand, const unsigned char *msg32, const unsigned char *t33, const unsigned char *expected_sig) {
    unsigned char sig[65];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pk, pk_expected;

    CHECK(secp256k1_keypair_create(ctx, &keypair, sk));
    CHECK(secp256k1_schnorr_adaptor_presign(ctx, sig, msg32, &keypair, t33, aux_rand));
    CHECK(secp256k1_memcmp_var(sig, expected_sig, 65) == 0);

    CHECK(secp256k1_xonly_pubkey_parse(ctx, &pk_expected, pk_serialized));
    CHECK(secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &keypair));
    CHECK(secp256k1_memcmp_var(&pk, &pk_expected, sizeof(pk)) == 0);
    /*later for checking verify*/
}

void test_schnorr_adaptor_vectors(void) {
    {
        /* Test vector 0 */
        const unsigned char sk[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
        };
        const unsigned char pk[32] = {
            0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
            0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
            0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
            0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9
        };
        unsigned char aux_rand[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        const unsigned char msg[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        const unsigned char t[33] = {
            0x02, 0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D,
            0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0, 0x7C,
            0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C,
            0xA7, 0xAB, 0xAC, 0x09, 0xB9, 0x5C, 0x70, 0x9E, 0xE5
        };
        const unsigned char sig[65] = {
            0x02, 0x06, 0x09, 0x11, 0xFD, 0x59, 0x2B, 0xB8, 
            0xD2, 0x66, 0x19, 0x83, 0x80, 0xE6, 0xB2, 0x80, 
            0x11, 0xEC, 0xBF, 0x46, 0x17, 0xDD, 0x12, 0xBF, 
            0xBF, 0xD4, 0x25, 0xFA, 0x78, 0x66, 0xF7, 0x80, 
            0xC8, 0xB6, 0x52, 0xB4, 0xB9, 0x5A, 0x20, 0xA8, 
            0x10, 0x51, 0xFA, 0x05, 0x09, 0x6E, 0x72, 0xD2, 
            0xDF, 0x31, 0x0A, 0x74, 0x19, 0x31, 0xF7, 0xA8, 
            0xFD, 0xCF, 0x5E, 0x70, 0x0E, 0x61, 0xCF, 0x6F, 0x1F
        };
        test_schnorr_adaptor_vectors_check_presigning(sk, pk, aux_rand, msg, t, sig);
    };
    {
        /* Test vector 1 */
        const unsigned char sk[32] = {
            0xB7, 0xE1, 0x51, 0x62, 0x8A, 0xED, 0x2A, 0x6A,
            0xBF, 0x71, 0x58, 0x80, 0x9C, 0xF4, 0xF3, 0xC7,
            0x62, 0xE7, 0x16, 0x0F, 0x38, 0xB4, 0xDA, 0x56,
            0xA7, 0x84, 0xD9, 0x04, 0x51, 0x90, 0xCF, 0xEF
        };
        const unsigned char pk[32] = {
            0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
            0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
            0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
            0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59
        };
        unsigned char aux_rand[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        };
        const unsigned char msg[32] = {
            0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
            0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
            0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
            0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89
        };
        const unsigned char t[33] = {
            0x02, 0x2F, 0x8B, 0xDE, 0x4D, 0x1A, 0x07, 0x20, 
            0x93, 0x55, 0xB4, 0xA7, 0x25, 0x0A, 0x5C, 0x51, 
            0x28, 0xE8, 0x8B, 0x84, 0xBD, 0xDC, 0x61, 0x9A, 
            0xB7, 0xCB, 0xA8, 0xD5, 0x69, 0xB2, 0x40, 0xEF, 0xE4
        };
        const unsigned char sig[65] = {
            0x02, 0x52, 0x1D, 0xC0, 0x77, 0xDF, 0xEC, 0xCF, 
            0x0F, 0x20, 0x6D, 0x25, 0xDA, 0xA6, 0xCC, 0xC1, 
            0x08, 0x0C, 0x1E, 0xA6, 0xCE, 0x83, 0xFD, 0x25, 
            0x71, 0x69, 0xC5, 0x0E, 0xA6, 0xFD, 0xF2, 0xFE, 
            0x27, 0x6E, 0x2A, 0x40, 0x8E, 0x60, 0x83, 0x9A, 
            0xE9, 0x5C, 0xFF, 0xF2, 0x0F, 0x52, 0xC9, 0xA2, 
            0xF2, 0xFA, 0x22, 0xB4, 0xDA, 0x79, 0x5B, 0x73, 
            0x34, 0x6B, 0x82, 0xA5, 0x22, 0xBF, 0xC5, 0x69, 0xB6
        };
        test_schnorr_adaptor_vectors_check_presigning(sk, pk, aux_rand, msg, t, sig);
    };
    {
        /* Test vector 2 */
        const unsigned char sk[32] = {
            0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
            0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 
            0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
            0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x14, 0xE5, 0xC9
        };
        const unsigned char pk[32] = {
            0xDD, 0x30, 0x8A, 0xFE, 0xC5, 0x77, 0x7E, 0x13, 
            0x12, 0x1F, 0xA7, 0x2B, 0x9C, 0xC1, 0xB7, 0xCC, 
            0x01, 0x39, 0x71, 0x53, 0x09, 0xB0, 0x86, 0xC9, 
            0x60, 0xE1, 0x8F, 0xD9, 0x69, 0x77, 0x4E, 0xB8
        };
        unsigned char aux_rand[32] = {
            0xC8, 0x7A, 0xA5, 0x38, 0x24, 0xB4, 0xD7, 0xAE, 
            0x2E, 0xB0, 0x35, 0xA2, 0xB5, 0xBB, 0xBC, 0xCC, 
            0x08, 0x0E, 0x76, 0xCD, 0xC6, 0xD1, 0x69, 0x2C, 
            0x4B, 0x0B, 0x62, 0xD7, 0x98, 0xE6, 0xD9, 0x04
        };
        const unsigned char msg[32] = {
            0x7E, 0x2D, 0x58, 0xD8, 0xB3, 0xBC, 0xDF, 0x1A, 
            0xBA, 0xDE, 0xC7, 0x82, 0x90, 0x54, 0xF9, 0x0D, 
            0xDA, 0x98, 0x05, 0xAA, 0xB5, 0x6C, 0x77, 0x33, 
            0x30, 0x24, 0xB9, 0xD0, 0xA5, 0x08, 0xB7, 0x5C
        };
        const unsigned char t[33] = {
            0x02, 0x5C, 0xBD, 0xF0, 0x64, 0x6E, 0x5D, 0xB4, 
            0xEA, 0xA3, 0x98, 0xF3, 0x65, 0xF2, 0xEA, 0x7A, 
            0x0E, 0x3D, 0x41, 0x9B, 0x7E, 0x03, 0x30, 0xE3, 
            0x9C, 0xE9, 0x2B, 0xDD, 0xED, 0xCA, 0xC4, 0xF9, 0xBC
        };
        const unsigned char sig[65] = {
            0x03, 0xEE, 0x01, 0x73, 0x70, 0x80, 0xBD, 0xCC, 
            0x0D, 0xB6, 0x11, 0xC3, 0x0B, 0x9D, 0x29, 0x52, 
            0x24, 0x5C, 0x07, 0xEA, 0x81, 0xD2, 0x00, 0x24, 
            0xB4, 0x93, 0x13, 0xE2, 0x61, 0x1C, 0x20, 0xA5, 
            0xE3, 0xF4, 0xE2, 0x0A, 0x0E, 0xDA, 0xE1, 0xB0, 
            0xBB, 0xC7, 0x89, 0xBC, 0x55, 0xC0, 0x4E, 0x80, 
            0xE7, 0x03, 0x1C, 0xAF, 0xAE, 0x50, 0x56, 0xC8, 
            0x18, 0x19, 0x90, 0xC9, 0x3D, 0x3B, 0xD3, 0x7B, 0xD7
        };
        test_schnorr_adaptor_vectors_check_presigning(sk, pk, aux_rand, msg, t, sig);
    };
    {
        /* Test vector 3 */
        const unsigned char sk[32] = {
            0x0B, 0x43, 0x2B, 0x26, 0x77, 0x93, 0x73, 0x81, 
            0xAE, 0xF0, 0x5B, 0xB0, 0x2A, 0x66, 0xEC, 0xD0, 
            0x12, 0x77, 0x30, 0x62, 0xCF, 0x3F, 0xA2, 0x54, 
            0x9E, 0x44, 0xF5, 0x8E, 0xD2, 0x40, 0x17, 0x10
        };
        const unsigned char pk[32] = {
            0x25, 0xD1, 0xDF, 0xF9, 0x51, 0x05, 0xF5, 0x25, 
            0x3C, 0x40, 0x22, 0xF6, 0x28, 0xA9, 0x96, 0xAD, 
            0x3A, 0x0D, 0x95, 0xFB, 0xF2, 0x1D, 0x46, 0x8A, 
            0x1B, 0x33, 0xF8, 0xC1, 0x60, 0xD8, 0xF5, 0x17
        };
        unsigned char aux_rand[32] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        const unsigned char msg[32] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        const unsigned char t[33] = {
            0x02, 0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D, 
            0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0, 0x7C, 
            0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C, 
            0xA7, 0xAB, 0xAC, 0x09, 0xB9, 0x5C, 0x70, 0x9E, 0xE5
        };
        const unsigned char sig[65] = {
            0x03, 0xEE, 0x14, 0xD2, 0xCA, 0x24, 0xD9, 0xD8, 
            0x47, 0x47, 0xB4, 0x34, 0xE5, 0x19, 0x50, 0x4E, 
            0xC9, 0xFC, 0x6A, 0xE4, 0xEE, 0xB9, 0x57, 0x81, 
            0xA0, 0xAA, 0xE5, 0xF6, 0x73, 0xEC, 0x08, 0x88, 
            0x37, 0x0E, 0x46, 0x6F, 0xC1, 0x59, 0x5B, 0x16, 
            0xE9, 0x45, 0x6D, 0xC8, 0x4B, 0xD7, 0x15, 0x39, 
            0x83, 0x57, 0xAF, 0x00, 0x3F, 0x74, 0x7B, 0x73, 
            0x93, 0x53, 0x2B, 0xB0, 0x55, 0x1B, 0x78, 0x57, 0xA1
        };
        test_schnorr_adaptor_vectors_check_presigning(sk, pk, aux_rand, msg, t, sig);
    };
    {
        /* Test vector 4 */
        const unsigned char sk[32] = {
            0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
            0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 
            0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
            0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x14, 0xE5, 0xC9
        };
        const unsigned char pk[32] = {
            0xDD, 0x30, 0x8A, 0xFE, 0xC5, 0x77, 0x7E, 0x13, 
            0x12, 0x1F, 0xA7, 0x2B, 0x9C, 0xC1, 0xB7, 0xCC, 
            0x01, 0x39, 0x71, 0x53, 0x09, 0xB0, 0x86, 0xC9, 
            0x60, 0xE1, 0x8F, 0xD9, 0x69, 0x77, 0x4E, 0xB8
        };
        unsigned char aux_rand[32] = {
            0xC8, 0x7A, 0xA5, 0x38, 0x24, 0xB4, 0xD7, 0xAE, 
            0x2E, 0xB0, 0x35, 0xA2, 0xB5, 0xBB, 0xBC, 0xCC, 
            0x08, 0x0E, 0x76, 0xCD, 0xC6, 0xD1, 0x69, 0x2C, 
            0x4B, 0x0B, 0x62, 0xD7, 0x98, 0xE6, 0xD9, 0x04
        };
        const unsigned char msg[32] = {
            0x7E, 0x2D, 0x58, 0xD8, 0xB3, 0xBC, 0xDF, 0x1A, 
            0xBA, 0xDE, 0xC7, 0x82, 0x90, 0x54, 0xF9, 0x0D, 
            0xDA, 0x98, 0x05, 0xAA, 0xB5, 0x6C, 0x77, 0x33, 
            0x30, 0x24, 0xB9, 0xD0, 0xA5, 0x08, 0xB7, 0x5C
        };
        const unsigned char t[33] = {
            0x03, 0x5C, 0xBD, 0xF0, 0x64, 0x6E, 0x5D, 0xB4, 
            0xEA, 0xA3, 0x98, 0xF3, 0x65, 0xF2, 0xEA, 0x7A, 
            0x0E, 0x3D, 0x41, 0x9B, 0x7E, 0x03, 0x30, 0xE3, 
            0x9C, 0xE9, 0x2B, 0xDD, 0xED, 0xCA, 0xC4, 0xF9, 0xBC
        };
        const unsigned char sig[65] = {
            0x02, 0x7C, 0x03, 0x7F, 0xE8, 0xF4, 0xD6, 0x8D, 
            0xFB, 0x2A, 0x0D, 0x21, 0xAB, 0x23, 0xD5, 0x9F, 
            0xB4, 0xF1, 0x82, 0xC6, 0x01, 0xAB, 0x2B, 0xA1, 
            0x11, 0x5C, 0x12, 0x13, 0x43, 0x01, 0x3B, 0xBA, 
            0x49, 0x2A, 0xDC, 0x8D, 0x8F, 0x7B, 0x6F, 0xAE, 
            0xF5, 0xE8, 0x1B, 0x9C, 0x0B, 0x7A, 0xA8, 0xEE, 
            0x57, 0xE5, 0x0A, 0x48, 0xBB, 0xEC, 0x52, 0x5C, 
            0x11, 0x9B, 0x90, 0x36, 0x53, 0x21, 0xC2, 0x1B, 0xAD
        };
        test_schnorr_adaptor_vectors_check_presigning(sk, pk, aux_rand, msg, t, sig);
    };
}

void run_schnorr_adaptor_tests(void) {
    int i;
    run_nonce_function_bip340_tests();

    test_schnorr_adaptor_api();
    test_schnorrsig_sha256_tagged();
    test_schnorr_adaptor_vectors();
}

#endif
