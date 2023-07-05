/**********************************************************************
 * Copyright (c) 2023 Zhe Pang                                        *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_H
#define _SECP256K1_MODULE_SCHNORR_ADAPTOR_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorr_adaptor.h"
#include "../../hash.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/nonce")||SHA256("BIP0340/nonce"). */
static void secp256k1_nonce_function_bip340_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x46615b35ul;
    sha->s[1] = 0xf4bfbff7ul;
    sha->s[2] = 0x9f8dc671ul;
    sha->s[3] = 0x83627ab3ul;
    sha->s[4] = 0x60217180ul;
    sha->s[5] = 0x57358661ul;
    sha->s[6] = 0x21a29e54ul;
    sha->s[7] = 0x68b07b4cul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/aux")||SHA256("BIP0340/aux"). */
static void secp256k1_nonce_function_bip340_sha256_tagged_aux(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x24dd3219ul;
    sha->s[1] = 0x4eba7e70ul;
    sha->s[2] = 0xca0fabb9ul;
    sha->s[3] = 0x0fa3166dul;
    sha->s[4] = 0x3afbe4b1ul;
    sha->s[5] = 0x4c44df97ul;
    sha->s[6] = 0x4aac2739ul;
    sha->s[7] = 0x249e850aul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_bip340 to derive the nonce exactly as stated in BIP-340
 * by using the correct tagged hash function. */
static const unsigned char bip340_algo[13] = "BIP0340/nonce";

static int nonce_function_bip340(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *xonly_t32, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        secp256k1_nonce_function_bip340_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(&sha, data, 32);
        secp256k1_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    } else {
        /* Precomputed TaggedHash("BIP0340/aux", 0x0000...00); */
        static const unsigned char ZERO_MASK[32] = {
              84, 241, 105, 207, 201, 226, 229, 114,
             116, 128,  68,  31, 144, 186,  37, 196,
             136, 244,  97, 199,  11,  94, 165, 220,
             170, 247, 175, 105, 39,  10, 165,  20
        };
        for (i = 0; i < 32; i++) {
            masked_key[i] = key32[i] ^ ZERO_MASK[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithms. If this nonce function is used in BIP-340 signing as defined
     * in the spec, an optimized tagging implementation is used. */
    if (algolen == sizeof(bip340_algo)
            && secp256k1_memcmp_var(algo, bip340_algo, algolen) == 0) {
        secp256k1_nonce_function_bip340_sha256_tagged(&sha);
    } else {
        secp256k1_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash masked-key||t||pk||msg using the tagged hash as per the spec */
    secp256k1_sha256_write(&sha, masked_key, 32);
    secp256k1_sha256_write(&sha, xonly_t32, 32);
    secp256k1_sha256_write(&sha, xonly_pk32, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, nonce32);
    return 1;
}

const secp256k1_nonce_function_hardened secp256k1_nonce_function_bip340 = nonce_function_bip340;

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge"). */
static void secp256k1_schnorrsig_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x9cecba11ul;
    sha->s[1] = 0x23925381ul;
    sha->s[2] = 0x11679112ul;
    sha->s[3] = 0xd1627e0ful;
    sha->s[4] = 0x97c87550ul;
    sha->s[5] = 0x003cc765ul;
    sha->s[6] = 0x90f61164ul;
    sha->s[7] = 0x33e9b66aul;
    sha->bytes = 64;
}

static void secp256k1_schnorrsig_challenge(secp256k1_scalar* e, const unsigned char *r32, const unsigned char *msg32, const unsigned char *pubkey32)
{
    unsigned char buf[32];
    secp256k1_sha256 sha;

    /* tagged hash(r.x, pk.x, msg) */
    secp256k1_schnorrsig_sha256_tagged(&sha);
    secp256k1_sha256_write(&sha, r32, 32);
    secp256k1_sha256_write(&sha, pubkey32, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, buf);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    secp256k1_scalar_set_b32(e, buf, NULL);
}

static int secp256k1_schnorr_adaptor_presign_internal(const secp256k1_context *ctx, unsigned char *sig65, const unsigned char *msg32, const secp256k1_keypair *keypair, secp256k1_nonce_function_hardened noncefp, const unsigned char *t33, void *ndata) {
    secp256k1_scalar sk;
    secp256k1_scalar e;
    secp256k1_scalar k;
    secp256k1_gej rj;
    secp256k1_gej rj1;
    secp256k1_gej r0j;
    secp256k1_ge pk;
    secp256k1_ge r;
    secp256k1_ge r0;
    secp256k1_ge t;
    unsigned char nonce32[32] = {0};
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    size_t size = 33;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig65 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(t33 != NULL);

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_bip340;
    }

    ret &= secp256k1_keypair_load(ctx, &sk, &pk, keypair);

    if (secp256k1_fe_is_odd(&pk.y)) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    /* d */
    secp256k1_scalar_get_b32(seckey, &sk);
    /* bytes_from_point(P) */ 
    secp256k1_fe_get_b32(pk_buf, &pk.x); 

    ret &= !!noncefp(nonce32, msg32, seckey, &t33[1], pk_buf, bip340_algo, sizeof(bip340_algo), ndata);
    /* k0 */ 
    secp256k1_scalar_set_b32(&k, nonce32, NULL); 
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    /* R = k0*G */ 
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k); 
    secp256k1_ge_set_gej(&r, &rj);

    /* T = cpoint(T) */
    ret &= !!secp256k1_eckey_pubkey_parse(&t, t33, 33);

    /* We declassify r to allow using it as a branch point. This is fine
     * because r is not a secret.  */
    secp256k1_declassify(ctx, &r, sizeof(r));
    secp256k1_fe_normalize_var(&r.y);
    if (secp256k1_fe_is_odd(&r.y)) {
        secp256k1_scalar_negate(&k, &k);
    }

    /* R' = k*G + T, can use gej_add_ge_var since r and t aren't secret */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj1, &k);
    secp256k1_gej_add_ge_var(&r0j, &rj1, &t, NULL); 
    secp256k1_ge_set_gej(&r0, &r0j);

    secp256k1_eckey_pubkey_serialize(&r0, sig65, &size, 1);

    secp256k1_schnorrsig_challenge(&e, &sig65[1], msg32, pk_buf);
    secp256k1_scalar_mul(&e, &e, &sk);
    /* k + e * d */
    secp256k1_scalar_add(&e, &e, &k); 
    secp256k1_scalar_get_b32(&sig65[33], &e);

    secp256k1_memczero(sig65, 65, !ret);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);
    memset(seckey, 0, sizeof(seckey));

    return ret;
}

int secp256k1_schnorr_adaptor_presign(const secp256k1_context* ctx, unsigned char *sig65, const unsigned char *msg32, const secp256k1_keypair *keypair, const unsigned char *t33, const unsigned char *aux_rand32) {
    /* We cast away const from the passed aux_rand32 argument since we know the default nonce function does not modify it. */
    return secp256k1_schnorr_adaptor_presign_internal(ctx, sig65, msg32, keypair, secp256k1_nonce_function_bip340, t33, (unsigned char*)aux_rand32);
}

static int secp256k1_schnorr_adaptor_extract_t(const secp256k1_context* ctx, unsigned char *t33, const unsigned char *sig65, const unsigned char *msg32, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_scalar s0;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge r;
    secp256k1_ge pk;
    secp256k1_gej pkj;
    secp256k1_ge r0;
    secp256k1_ge t;
    secp256k1_gej tj;
    unsigned char buf[32];
    size_t size = 33;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(t33 != NULL);
    ARG_CHECK(sig65 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);

    /* P */
    ret &= !!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey);

    /* s0 */
    secp256k1_scalar_set_b32(&s0, &sig65[33], &overflow);
    ret &= !overflow;

    /* R0 */
    ret &= !!secp256k1_eckey_pubkey_parse(&r0, &sig65[0], 33);

    /* Compute e */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &sig65[1], msg32, buf);

    /* Compute rj = s0*G + (-e) * pkj */
    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&pkj, &pk);
    secp256k1_ecmult(&rj, &pkj, &e, &s0);

    /* R */
    secp256k1_ge_set_gej_var(&r, &rj);
    ret &= !secp256k1_ge_is_infinity(&r);
    secp256k1_fe_normalize_var(&r.y);
    ret &= !secp256k1_fe_is_odd(&r.y);

    /* T = R0 + (- R) */
    secp256k1_gej_neg(&rj, &rj);
    secp256k1_gej_add_ge_var(&tj, &rj, &r0, NULL);
    secp256k1_ge_set_gej(&t, &tj);
    secp256k1_eckey_pubkey_serialize(&t, t33, &size, 1);

    secp256k1_memczero(t33, 33, !ret);
    secp256k1_scalar_clear(&s0);

    return ret;
}

#endif
