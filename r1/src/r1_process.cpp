#include "util.cpp"

using namespace zmq;


int zmq_send(uint8_t* ct, size_t ctlen,
             uint8_t* ctsig, size_t ctsiglen,
             uint8_t* r1_pk, size_t r1_pklen,
             uint8_t* r1_pk_cert, size_t r1_pk_certlen)
{
    static zmq::context_t ctx;
    char                  *socket = (char*) ("tcp://" + r1_ip_address).c_str();
    zmq::socket_t         pub(ctx, ZMQ_REQ);

    pub.connect(socket);

    zmq::message_t msg1 (ct, ctlen);
    pub.send(msg1, ZMQ_SNDMORE);
    
    zmq::message_t msg2 (ctsig, ctsiglen);
    pub.send(msg2, ZMQ_SNDMORE);
    
    zmq::message_t msg3 (r1_pk, r1_pklen);
    pub.send(msg3, ZMQ_SNDMORE);
    
    zmq::message_t msg4 (r1_pk_cert, r1_pk_certlen);
    pub.send(msg4, ZMQ_NULL);


    return 0;
}


int zmq_recv()
{
    static zmq::context_t ctx(1);
    uint8_t               *ct, *ctsig, *cc_pk, *cc_pk_cert;
    size_t                length; 
    char                  *socket = (char*) ("tcp://" + r1_ip_broadcast).c_str();
    zmq::socket_t         sub(ctx, ZMQ_REP);
    zmq::message_t        payload;


    sub.bind(socket);

    sub.recv(&payload, ZMQ_NULL);
    ct = (uint8_t*) payload.data();
    save_array("data/cc/tmp/ct", ct, payload.size());

    sub.recv(&payload, ZMQ_NULL);
    ctsig = (uint8_t*) payload.data();
    save_array("data/cc/tmp/ct_sig", ctsig, payload.size());

    sub.recv(&payload, ZMQ_NULL);
    cc_pk = (uint8_t*) payload.data();
    save_array("data/cc/tmp/d_pk", cc_pk, payload.size());

    sub.recv(&payload, ZMQ_NULL);
    cc_pk_cert = (uint8_t*) payload.data();
    save_array("data/cc/tmp/d_pk_cert", cc_pk_cert, payload.size());
    

    return 0;
}


/**
 * Function Name: r1_process
 *
 * Description:
 * Raspberry1 process
 * 
 * @param signer     Signer instance
 *
 * @return 0 on success, 1 on failure
 */
OQS_STATUS r1_process()
{
    OQS_KEM     *kem = NULL;
    OQS_SIG     *sig = NULL;
	uint8_t     *ca_d_pk;
    uint8_t     *cc_d_pk, *cc_ct_sig, *cc_d_pk_cert;
    uint8_t     *r1_k_pk, *r1_k_sk, *r1_d_pk, *r1_d_sk, *r1_sig_d_pk, *r1_ct_sig, *r1_d_pk_cert;
    uint8_t     *r2_k_pk;
    uint8_t     *ct;
    uint8_t     *k1, *k2, *message;
	OQS_STATUS  rc, ret = OQS_ERROR;
	int         rv;
    size_t      length;

    auto decaps_start        = std::chrono::high_resolution_clock::now();
    auto decaps_end          = std::chrono::high_resolution_clock::now();
    auto encaps_start        = std::chrono::high_resolution_clock::now();
    auto encaps_end          = std::chrono::high_resolution_clock::now();
    auto verif_start         = std::chrono::high_resolution_clock::now();
    auto verif_end           = std::chrono::high_resolution_clock::now();
    auto sign_start          = std::chrono::high_resolution_clock::now();
    auto sign_end            = std::chrono::high_resolution_clock::now();
    auto decaps_time         = std::chrono::duration_cast<std::chrono::nanoseconds>(decaps_end - decaps_start);
    auto encaps_time         = std::chrono::duration_cast<std::chrono::nanoseconds>(encaps_end - encaps_start);
    auto verif_time          = std::chrono::duration_cast<std::chrono::nanoseconds>(verif_start - verif_start);
    auto sign_time           = std::chrono::duration_cast<std::chrono::nanoseconds>(sign_start - sign_start);

    
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
    r1_k_sk         = (uint8_t*) malloc(kem->length_secret_key);
    r1_d_pk         = (uint8_t*) malloc(sig->length_public_key);
    r1_d_sk         = (uint8_t*) malloc(sig->length_secret_key);
    r1_ct_sig       = (uint8_t*) malloc(sig->length_signature);
    r1_d_pk_cert    = (uint8_t*) malloc(sig->length_signature);
    r2_k_pk         = (uint8_t*) malloc(kem->length_public_key);
    cc_d_pk         = (uint8_t*) malloc(sig->length_public_key);
    cc_ct_sig       = (uint8_t*) malloc(sig->length_signature);
    cc_d_pk_cert    = (uint8_t*) malloc(sig->length_signature);
    ca_d_pk         = (uint8_t*) malloc(sig->length_public_key);
    message         = (uint8_t*) malloc(kem->length_shared_secret);

    zmq_recv();
    load_array("data/cc/tmp/ct", &ct, 2 * kem->length_ciphertext);
    load_array("data/cc/tmp/ct_sig", &cc_ct_sig, sig->length_signature);
    load_array("data/cc/tmp/d_pk", &cc_d_pk, sig->length_public_key);
    load_array("data/cc/tmp/d_pk_cert", &cc_d_pk_cert, sig->length_signature);

    load_array("data/ca/d_pk", &ca_d_pk, sig->length_public_key);
    load_array("data/r1/k_sk", &r1_k_sk, kem->length_secret_key);
    load_array("data/r1/k_pk", &r1_k_pk, kem->length_public_key);
    load_array("data/r1/d_pk", &r1_d_pk, sig->length_public_key);
    load_array("data/r1/d_sk", &r1_d_sk, sig->length_secret_key);
    load_array("data/r1/d_pk_cert", &r1_d_pk_cert, sig->length_signature);
    load_array("data/r2/k_pk", &r2_k_pk, kem->length_public_key);
    

    // verify CC's public key certification
    verif_start = std::chrono::high_resolution_clock::now();
    rc = OQS_SIG_verify(sig,
                        cc_d_pk, sig->length_public_key,
                        cc_d_pk_cert, sig->length_signature,
                        ca_d_pk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed\n");
		goto err;
	}
    verif_end = std::chrono::high_resolution_clock::now();
    // verify CC's ciphertext signature
    rc = OQS_SIG_verify(sig,
                        ct, 2 * kem->length_ciphertext,
                        cc_ct_sig, sig->length_signature,
                        cc_d_pk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed\n");
		goto err;
	}

    // Decapsulate the ciphertext
    decaps_start = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_decaps(kem, k1, ct, r1_k_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed\n");
		goto err;
	}
    decaps_end = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_decaps(kem, k2, ct + kem->length_ciphertext, r1_k_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed\n");
		goto err;
	}

    // Prepare the keys and certificates to send to R2
    encaps_start = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_encaps(kem, ct, k1, r2_k_pk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed\n");
		goto err;
	}
    encaps_end = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_encaps(kem, ct + kem->length_ciphertext, k2, r2_k_pk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed\n");
		goto err;
	}

    sign_start = std::chrono::high_resolution_clock::now();
    rc = OQS_SIG_sign(sig,
                      r1_ct_sig, &length,
                      ct, 2 * kem->length_ciphertext,
                      r1_d_sk);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
		goto err;
	}
    sign_end = std::chrono::high_resolution_clock::now();

    zmq_send(ct, 2 * kem->length_ciphertext,
             r1_ct_sig, sig->length_signature,
             r1_d_pk, sig->length_public_key,
             r1_d_pk_cert, sig->length_signature);


    decaps_time = std::chrono::duration_cast<std::chrono::nanoseconds>(decaps_end - decaps_start);
    encaps_time = std::chrono::duration_cast<std::chrono::nanoseconds>(encaps_end - encaps_start);
    verif_time  = std::chrono::duration_cast<std::chrono::nanoseconds>(verif_end - verif_start);
    sign_time   = std::chrono::duration_cast<std::chrono::nanoseconds>(sign_end - sign_start);

    printf("Kyber encapsulation runtime: %6.9f ms\n", encaps_time.count() / 1000000.0f);
    printf("Kyber decapsulation runtime: %6.9f ms\n", decaps_time.count() / 1000000.0f);
    printf("Dilithium signing runtime: %6.9f ms\n", sign_time.count() / 1000000.0f);
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
    OQS_MEM_insecure_free(r1_k_pk);
    OQS_MEM_insecure_free(r1_k_sk);
    OQS_MEM_insecure_free(r2_k_pk);
    OQS_MEM_insecure_free(ca_d_pk);
    OQS_MEM_insecure_free(message);
    OQS_MEM_insecure_free(cc_d_pk);
    OQS_MEM_insecure_free(cc_ct_sig);
    OQS_MEM_insecure_free(cc_d_pk_cert);

    return ret;
}
