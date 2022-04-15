#include <iostream>
#include <string.h>
#include <chrono>
#include "util.cpp"
#include "zmq.hpp"


int zmq_send(uint8_t* ct, size_t ctlen,
             uint8_t* ctsig, size_t ctsiglen,
             uint8_t* cc_pk, size_t cc_pklen,
             uint8_t* cc_pk_cert, size_t cc_pk_certlen)
{
    zmq::context_t ctx(1);
    char                  *socket = (char*) ("tcp://" + cc_ip_address).c_str();
    zmq::socket_t         pub(ctx, ZMQ_REQ);

    pub.connect(socket);

    zmq::message_t msg1 (ct, ctlen);
    pub.send(msg1, ZMQ_SNDMORE);
    
    zmq::message_t msg2 (ctsig, ctsiglen);
    pub.send(msg2, ZMQ_SNDMORE);
    
    zmq::message_t msg3 (cc_pk, cc_pklen);
    pub.send(msg3, ZMQ_SNDMORE);
    
    zmq::message_t msg4 (cc_pk_cert, cc_pk_certlen);
    pub.send(msg4, ZMQ_NULL);
    

    return 0;
}


/**
 * Function Name: cc_process
 *
 * Description:
 * CC process
 * 
 * @param signer     Signer instance
 *
 * @return 0 on success, 1 on failure
 */
OQS_STATUS cc_process()
{
    OQS_KEM     *kem = NULL;
    OQS_SIG     *sig = NULL;
    uint8_t     *ca_d_pk;
    uint8_t     *cc_d_pk, *cc_d_sk, *cc_ct_sig, *cc_d_pk_cert;
    uint8_t     *r1_k_pk;
    uint8_t     *ct;
    uint8_t     *k1, *k2;
	OQS_STATUS  rc, ret = OQS_ERROR;
	int         rv;
    size_t      length;

    auto kyber_start        = std::chrono::high_resolution_clock::now();
    auto kyber_end          = std::chrono::high_resolution_clock::now();
    auto kyber_time         = std::chrono::duration_cast<std::chrono::nanoseconds>(kyber_end - kyber_start);
    auto dilithium_start    = std::chrono::high_resolution_clock::now();
    auto dilithium_end      = std::chrono::high_resolution_clock::now();
    auto dilithium_time     = std::chrono::duration_cast<std::chrono::nanoseconds>(dilithium_start - dilithium_start);
    

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

    k1              = (uint8_t*) malloc(QUIBITEK_SIZE);
    k2              = (uint8_t*) malloc(QUIBITEK_SIZE);
    ct              = (uint8_t*) malloc(2 * kem->length_ciphertext);
    r1_k_pk         = (uint8_t*) malloc(kem->length_public_key);
    cc_d_pk         = (uint8_t*) malloc(sig->length_public_key);
    cc_d_sk         = (uint8_t*) malloc(sig->length_secret_key);
    cc_ct_sig       = (uint8_t*) malloc(sig->length_signature);
    cc_d_pk_cert    = (uint8_t*) malloc(sig->length_signature);
    ca_d_pk         = (uint8_t*) malloc(sig->length_public_key);

    load_array("data/r1/k_pk", &r1_k_pk, kem->length_public_key);
    load_array("data/cc/d_pk", &cc_d_pk, sig->length_public_key);
    load_array("data/cc/d_sk", &cc_d_sk, sig->length_secret_key);
    load_array("data/cc/d_pk_cert", &cc_d_pk_cert, sig->length_signature);
    load_array("data/quibitek/k1", &k1, QUIBITEK_SIZE);
    load_array("data/quibitek/k2", &k2, QUIBITEK_SIZE);
    load_array("data/ca/d_pk", &ca_d_pk, sig->length_public_key);


    kyber_start = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_encaps(kem, ct, k1, r1_k_pk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed\n");
		goto err;
	}
    kyber_end = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_encaps(kem, ct + kem->length_ciphertext, k2, r1_k_pk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed\n");
		goto err;
	}
    dilithium_start = std::chrono::high_resolution_clock::now();
    rc = OQS_SIG_sign(sig,
                      cc_ct_sig, &length,
                      ct, 2 * kem->length_ciphertext,
                      cc_d_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
		goto err;
	}
    dilithium_end = std::chrono::high_resolution_clock::now();

    zmq_send(ct, 2 * kem->length_ciphertext,
             cc_ct_sig, sig->length_signature,
             cc_d_pk, sig->length_public_key,
             cc_d_pk_cert, sig->length_signature);

    dilithium_time     = std::chrono::duration_cast<std::chrono::nanoseconds>(dilithium_end - dilithium_start);
    kyber_time         = std::chrono::duration_cast<std::chrono::nanoseconds>(kyber_end - kyber_start);

    printf("Kyber encapsulation runtime: %6.9f ms\n", kyber_time.count() / 1000000.0f);
    printf("Dilithium signing runtime: %6.9f ms\n", dilithium_time.count() / 1000000.0f);

    ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;

cleanup:
    OQS_KEM_free(kem);
    OQS_SIG_free(sig);
    OQS_MEM_insecure_free(k1);
    OQS_MEM_insecure_free(k2);
    OQS_MEM_insecure_free(ct);
    OQS_MEM_insecure_free(r1_k_pk);
    OQS_MEM_insecure_free(cc_d_pk);
    OQS_MEM_insecure_free(cc_d_sk);
    OQS_MEM_insecure_free(cc_ct_sig);
    OQS_MEM_insecure_free(cc_d_pk_cert);

    return ret;
}
