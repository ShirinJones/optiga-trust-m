#include "optiga_cert.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/base64.h"
#include "mbedtls/ssl.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include <inttypes.h>
#include <string.h>

static const char *TAG = "OPTIGA_CSR";

// Wrapper function that matches mbedtls expected signature
static int optiga_rng_wrapper(void *ctx, unsigned char *output, size_t output_len)
{
    // Use a proper RNG implementation here
    // For now, use a simple implementation that uses ESP32's hardware RNG
    for (size_t i = 0; i < output_len; i++) {
        output[i] = esp_random() & 0xFF;
    }
    return 0;
}

int generate_csr_with_optiga(const char *common_name, uint8_t *pem_buffer, size_t pem_size) {
    int ret = 0;
    mbedtls_x509write_csr csr_ctx;
    mbedtls_pk_context pk_ctx;
    uint8_t der_buffer[1024];
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t offset;

    ESP_LOGI(TAG, "Free heap: %u bytes", (unsigned int)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

    // Initialize structures
    mbedtls_x509write_csr_init(&csr_ctx);
    mbedtls_pk_init(&pk_ctx);

    ESP_LOGI(TAG, "Free heap: %u bytes", (unsigned int)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

    // Set the subject name
    char subject[128];
    snprintf(subject, sizeof(subject), "CN=%s", common_name);
    if ((ret = mbedtls_x509write_csr_set_subject_name(&csr_ctx, subject)) != 0) {
        ESP_LOGE(TAG, "Failed to set subject name: -0x%04X", -ret);
        goto cleanup;
    }

    // Get public key from OPTIGA
    if ((ret = optiga_get_public_key(&public_key, &public_key_len, &offset)) != 0) {
        ESP_LOGE(TAG, "Failed to get OPTIGA public key");
        goto cleanup;
    }

    ESP_LOGI(TAG, "OPTIGA public key format: 0x%02X", public_key[offset]);
    ESP_LOG_BUFFER_HEXDUMP(TAG, public_key + offset, public_key_len - offset > 32 ? 32 : public_key_len - offset, ESP_LOG_INFO);

    // Setup PK context for EC key
    ret = mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to setup PK context: -0x%04X", -ret);
        goto cleanup;
    }

    // Load the SECP256R1 curve explicitly
    ret = mbedtls_ecp_group_load(&mbedtls_pk_ec(pk_ctx)->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load EC group: -0x%04X", -ret);
        goto cleanup;
    }

    // Parse the public key directly into the PK context
    // Make sure we're using the correct offset and length
    ret = mbedtls_ecp_point_read_binary(&mbedtls_pk_ec(pk_ctx)->grp,
                                       &mbedtls_pk_ec(pk_ctx)->Q,
                                       public_key + offset,
                                       public_key_len - offset);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to parse public key: -0x%04X", -ret);
        ESP_LOGI(TAG, "Public key length: %d, offset: %d", public_key_len, offset);
        ESP_LOG_BUFFER_HEXDUMP(TAG, public_key + offset, public_key_len - offset, ESP_LOG_ERROR);
        goto cleanup;
    }

    // Set the key and continue with CSR generation...
    mbedtls_x509write_csr_set_key(&csr_ctx, &pk_ctx);
    mbedtls_x509write_csr_set_md_alg(&csr_ctx, MBEDTLS_MD_SHA256);

    ESP_LOGI(TAG, "Free heap: %u bytes", (unsigned int)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));

    // Generate DER CSR first
    ret = mbedtls_x509write_csr_der(&csr_ctx, der_buffer, sizeof(der_buffer),
                                    optiga_rng_wrapper, NULL);
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to write DER CSR: -0x%04X", -ret);
        ESP_LOGI(TAG, "Free heap: %u bytes", (unsigned int)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
        goto cleanup;
    }

    // Convert DER to PEM
    ret = mbedtls_x509write_csr_pem(&csr_ctx, pem_buffer, pem_size,
                                    optiga_rng_wrapper, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to convert DER to PEM: -0x%04X", -ret);
        goto cleanup;
    }

    ESP_LOGI(TAG, "CSR generated successfully");

cleanup:
    mbedtls_x509write_csr_free(&csr_ctx);
    mbedtls_pk_free(&pk_ctx);
    return ret;
}
