#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <oqs/oqs.h>
#include "util.cpp"

/**
 * Function Name: key_gen
 *
 * Description:
 * Key generation process
 * 
 * @param signer     Signer instance
 *
 * @return 0 on success, 1 on failure
 */
OQS_STATUS key_gen()
{
    OQS_KEM     *kem = NULL;
    OQS_SIG     *sig = NULL;
	uint8_t     *ca_d_pk, *ca_d_sk;
    uint8_t     *cc_k_pk, *cc_k_sk, *cc_d_pk, *cc_d_sk, *cc_sig_d_pk;
    uint8_t     *r1_k_pk, *r1_k_sk, *r1_d_pk, *r1_d_sk, *r1_sig_d_pk;
    uint8_t     *r2_k_pk, *r2_k_sk, *r2_d_pk, *r2_d_sk, *r2_sig_d_pk;
    uint8_t     k1[QUIBITEK_SIZE] = {0x5a, 0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x04, 0x01, 0x87, 0x18, 0x3f, 0xc5, 0xc8,
                                     0x1e, 0x84, 0x1e, 0x1b, 0xe4, 0x6e, 0x2c, 0x1e,
                                     0xba, 0x7f, 0x37, 0x55, 0x37, 0xe9, 0xd3, 0x7b},
                k2[QUIBITEK_SIZE] = {0x5a, 0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x03, 0x01, 0x87, 0x18, 0x3f, 0xc5, 0xc8,
                                     0x1e, 0x84, 0x1e, 0x1b, 0xe4, 0x6e, 0x2c, 0x1e,
                                     0xba, 0x7f, 0x37, 0x55, 0x37, 0xe9, 0xd3, 0x7b};
	OQS_STATUS  rc, ret = OQS_ERROR;
	int         rv;
    size_t      siglen;


	kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
	if (kem == NULL) {
		fprintf(stderr, "ERROR: OQS_KEM_new failed\n");
		goto err;
	}

    sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
	if (sig == NULL) {
		fprintf(stderr, "ERROR: OQS_SIG_new failed\n");
		goto err;
	}

    // Memory allocation
    cc_k_pk     = (uint8_t*) malloc(kem->length_public_key);
	cc_k_sk     = (uint8_t*) malloc(kem->length_secret_key);
    r1_k_pk     = (uint8_t*) malloc(kem->length_public_key);
	r1_k_sk     = (uint8_t*) malloc(kem->length_secret_key);
    r2_k_pk     = (uint8_t*) malloc(kem->length_public_key);
	r2_k_sk     = (uint8_t*) malloc(kem->length_secret_key);
    ca_d_pk     = (uint8_t*) malloc(sig->length_public_key);
	ca_d_sk     = (uint8_t*) malloc(sig->length_secret_key);
    cc_d_pk     = (uint8_t*) malloc(sig->length_public_key);
	cc_d_sk     = (uint8_t*) malloc(sig->length_secret_key);
    r1_d_pk     = (uint8_t*) malloc(sig->length_public_key);
	r1_d_sk     = (uint8_t*) malloc(sig->length_secret_key);
    r2_d_pk     = (uint8_t*) malloc(sig->length_public_key);
	r2_d_sk     = (uint8_t*) malloc(sig->length_secret_key);
    cc_sig_d_pk = (uint8_t*) malloc(sig->length_signature);
    r1_sig_d_pk = (uint8_t*) malloc(sig->length_signature);
    r2_sig_d_pk = (uint8_t*) malloc(sig->length_signature);

    if (cc_k_pk == NULL || cc_k_sk == NULL || r1_k_pk == NULL || r1_k_sk == NULL || r2_k_pk == NULL ||
       r2_k_sk == NULL || ca_d_pk == NULL || ca_d_sk == NULL || cc_d_pk == NULL || cc_d_sk == NULL ||
       r1_d_pk == NULL || r1_d_sk == NULL || r2_d_pk == NULL || r2_d_sk == NULL || cc_sig_d_pk == NULL ||
       r1_sig_d_pk == NULL || r2_sig_d_pk == NULL)
    {
		fprintf(stderr, "ERROR: malloc failed\n");
		goto err;
	}

    // Kyber keys generation
    rc = OQS_KEM_keypair(kem, cc_k_pk, cc_k_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed\n");
		goto err;
	}
    rc = OQS_KEM_keypair(kem, r1_k_pk, r1_k_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed\n");
		goto err;
	}
    rc = OQS_KEM_keypair(kem, r2_k_pk, r2_k_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed\n");
		goto err;
	}

    // Dilithium keys generation
    rc = OQS_SIG_keypair(sig, ca_d_pk, ca_d_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
		goto err;
	}
    rc = OQS_SIG_keypair(sig, cc_d_pk, cc_d_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
		goto err;
	}
    rc = OQS_SIG_keypair(sig, r1_d_pk, r1_d_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
		goto err;
	}
    rc = OQS_SIG_keypair(sig, r2_d_pk, r2_d_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
		goto err;
	}

    // Sign public keys using secret master key
    rc = OQS_SIG_sign(sig,
                      cc_sig_d_pk, &siglen,
                      cc_d_pk, sig->length_public_key,
                      ca_d_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
		goto err;
	}
    rc = OQS_SIG_sign(sig,
                      r1_sig_d_pk, &siglen,
                      r1_d_pk, sig->length_public_key,
                      ca_d_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
		goto err;
	}
    rc = OQS_SIG_sign(sig,
                      r2_sig_d_pk, &siglen,
                      r2_d_pk, sig->length_public_key,
                      ca_d_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
		goto err;
	}


    // save keys into memory
    save_array("data/quibitek/k1", k1, sizeof(k1));
    save_array("data/quibitek/k2", k2, sizeof(k2));
    save_array("data/ca/d_pk", ca_d_pk, sig->length_public_key);
    save_array("data/ca/d_sk", ca_d_sk, sig->length_secret_key);

    save_array("data/cc/d_pk", cc_d_pk, sig->length_public_key);
    save_array("data/cc/d_sk", cc_d_sk, sig->length_secret_key);
    save_array("data/cc/k_pk", cc_k_pk, kem->length_public_key);
    save_array("data/cc/k_sk", cc_k_sk, kem->length_secret_key);
    save_array("data/cc/d_pk_cert", cc_sig_d_pk, sig->length_signature);

    save_array("data/r1/d_pk", r1_d_pk, sig->length_public_key);
    save_array("data/r1/d_sk", r1_d_sk, sig->length_secret_key);
    save_array("data/r1/k_pk", r1_k_pk, kem->length_public_key);
    save_array("data/r1/k_sk", r1_k_sk, kem->length_secret_key);
    save_array("data/r1/d_pk_cert", r1_sig_d_pk, sig->length_signature);

    save_array("data/r2/d_pk", r2_d_pk, sig->length_public_key);
    save_array("data/r2/d_sk", r2_d_sk, sig->length_secret_key);
    save_array("data/r2/k_pk", r2_k_pk, kem->length_public_key);
    save_array("data/r2/k_sk", r2_k_sk, kem->length_secret_key);
    save_array("data/r2/d_pk_cert", r2_sig_d_pk, sig->length_signature);

    // verify CC's public key certification
    rc = OQS_SIG_verify(sig,
                        cc_d_pk, sig->length_public_key,
                        cc_sig_d_pk, sig->length_signature,
                        ca_d_pk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed 2\n");
		goto err;
	}

    // printf("DEBUG: [-1]\n");
    // for (int i = 0 ; i < 10 ; i ++) {
    //     printf("%u ", ca_d_pk[i]);
    // }
    // printf("\n\n");


    ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;

cleanup:
    OQS_KEM_free(kem);
    OQS_SIG_free(sig);
    OQS_MEM_insecure_free(cc_k_sk);
    OQS_MEM_insecure_free(r1_k_pk);
    OQS_MEM_insecure_free(r1_k_sk);
    OQS_MEM_insecure_free(r2_k_pk);
    OQS_MEM_insecure_free(r2_k_sk);
    OQS_MEM_insecure_free(ca_d_pk);
    OQS_MEM_insecure_free(ca_d_sk);
    OQS_MEM_insecure_free(cc_d_pk);
    OQS_MEM_insecure_free(cc_d_sk);
    OQS_MEM_insecure_free(r1_d_pk);
    OQS_MEM_insecure_free(r1_d_sk);
    OQS_MEM_insecure_free(r2_d_pk);
    OQS_MEM_insecure_free(r2_d_sk);
    OQS_MEM_insecure_free(cc_sig_d_pk);
    OQS_MEM_insecure_free(r1_sig_d_pk);
    OQS_MEM_insecure_free(r2_sig_d_pk);

    return ret;
}
