#include "util.cpp"


int zmq_recv()
{
    static zmq::context_t ctx(1);
    uint8_t               *ct, *ctsig, *r1_pk, *r1_pk_cert;
    char                  *socket = (char*) ("tcp://" + r2_ip_broadcast).c_str();
    zmq::socket_t         sub(ctx, ZMQ_REP);
    zmq::message_t        payload;

    sub.bind(socket);

    sub.recv(&payload);
    ct = (uint8_t*) payload.data();
    save_array("data/r1/tmp/ct", ct, payload.size());

    sub.recv(&payload);
    ctsig = (uint8_t*) payload.data();
    save_array("data/r1/tmp/ct_sig", ctsig, payload.size());

    sub.recv(&payload);
    r1_pk = (uint8_t*) payload.data();
    save_array("data/r1/tmp/d_pk", r1_pk, payload.size());

    sub.recv(&payload);
    r1_pk_cert = (uint8_t*) payload.data();
    save_array("data/r1/tmp/d_pk_cert", r1_pk_cert, payload.size());
    

    return 0;
}


/**
 * Function Name: r2_process
 *
 * Description:
 * Raspberry2 process
 * 
 * @param signer     Signer instance
 *
 * @return 0 on success, 1 on failure
 */
OQS_STATUS r2_process()
{
    OQS_KEM     *kem = NULL;
    OQS_SIG     *sig = NULL;
	uint8_t     *ca_d_pk;
    uint8_t     *r1_d_pk, *r1_d_sk, *r1_sig_d_pk, *r1_ct_sig, *r1_d_pk_cert;
    uint8_t     *r2_k_sk, *r2_d_pk, *r2_d_sk;
    uint8_t     *ct;
    uint8_t     *k1, *k2, *message;
	OQS_STATUS  rc, ret = OQS_ERROR;
	int         rv;
    size_t      length;


    auto decaps_start        = std::chrono::high_resolution_clock::now();
    auto decaps_end          = std::chrono::high_resolution_clock::now();
    auto verif_start         = std::chrono::high_resolution_clock::now();
    auto verif_end           = std::chrono::high_resolution_clock::now();
    auto decaps_time         = std::chrono::duration_cast<std::chrono::nanoseconds>(decaps_end - decaps_start);
    auto verif_time          = std::chrono::duration_cast<std::chrono::nanoseconds>(verif_start - verif_start);


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
    r1_d_pk         = (uint8_t*) malloc(sig->length_public_key);
    r1_ct_sig       = (uint8_t*) malloc(sig->length_signature);
    r1_d_pk_cert    = (uint8_t*) malloc(sig->length_signature);
    r2_k_sk         = (uint8_t*) malloc(kem->length_secret_key);
    ca_d_pk         = (uint8_t*) malloc(sig->length_public_key);
    message         = (uint8_t*) malloc(kem->length_shared_secret);

    zmq_recv();
    load_array("data/r1/tmp/ct", &ct, 2 * kem->length_ciphertext);
    load_array("data/r1/tmp/ct_sig", &r1_ct_sig, sig->length_signature);
    load_array("data/r1/tmp/d_pk", &r1_d_pk, sig->length_public_key);
    load_array("data/r1/tmp/d_pk_cert", &r1_d_pk_cert, sig->length_signature);

    load_array("data/ca/d_pk", &ca_d_pk, sig->length_public_key);
    load_array("data/r2/k_sk", &r2_k_sk, kem->length_secret_key);


    // verify R1's public key certification
    verif_start = std::chrono::high_resolution_clock::now();
    rc = OQS_SIG_verify(sig,
                        r1_d_pk, sig->length_public_key,
                        r1_d_pk_cert, sig->length_signature,
                        ca_d_pk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed\n");
		goto err;
	}
    verif_end = std::chrono::high_resolution_clock::now();
    // verify R1's ciphertext signature
    rc = OQS_SIG_verify(sig,
                        ct, 2 * kem->length_ciphertext,
                        r1_ct_sig, sig->length_signature,
                        r1_d_pk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed\n");
		goto err;
	}

    // Decapsulate the ciphertext
    decaps_start = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_decaps(kem, k1, ct, r2_k_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed\n");
		goto err;
	}
    decaps_end = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_decaps(kem, k2, ct + kem->length_ciphertext, r2_k_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed\n");
		goto err;
	}

    decaps_time = std::chrono::duration_cast<std::chrono::nanoseconds>(decaps_end - decaps_start);
    verif_time  = std::chrono::duration_cast<std::chrono::nanoseconds>(verif_end - verif_start);

    printf("Kyber decapsulation runtime: %6.9f ms\n", decaps_time.count() / 1000000.0f);
    printf("Dilithium verification runtime: %6.9f ms\n", verif_time.count() / 1000000.0f);


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
    OQS_MEM_insecure_free(r1_ct_sig);
    OQS_MEM_insecure_free(r1_d_pk_cert);
    OQS_MEM_insecure_free(r1_d_pk);
    OQS_MEM_insecure_free(r2_k_sk);
    OQS_MEM_insecure_free(ca_d_pk);
    OQS_MEM_insecure_free(message);

    return ret;
}
