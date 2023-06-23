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
}

void run_schnorr_adaptor_tests(void) {
    int i;
    run_nonce_function_bip340_tests();

    test_schnorr_adaptor_api();
    test_schnorrsig_sha256_tagged();
    test_schnorr_adaptor_vectors();
}

#endif
