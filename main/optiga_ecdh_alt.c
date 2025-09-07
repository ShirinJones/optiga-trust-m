#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "optiga_crypt.h"
#include "pal_os_timer.h"
#include "esp_log.h"
#include "optiga_demo_shared.h"
#include "optiga_lib_types.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "optiga_cert.h"

static const char *TAG = "OPTIGA_ECDH_DEMO";

extern void optiga_crypt_event_completed(void *context, optiga_lib_status_t status);
extern volatile optiga_lib_status_t optiga_crypt_status;


// Global variable to store the last generated public key
static uint8_t optiga_public_key[200];
static size_t optiga_public_key_len = 0;
static uint8_t optiga_public_key_offset = 3;

// Function to get the OPTIGA public key for CSR generation
int optiga_get_public_key(uint8_t **public_key, size_t *public_key_len, uint8_t *offset) {
    if (optiga_public_key_len == 0) {
        ESP_LOGE(TAG, "No public key available. Call mbedtls_ecdh_gen_public first.");
        return -1;
    }

    *public_key = optiga_public_key;
    *public_key_len = optiga_public_key_len;
    *offset = optiga_public_key_offset;

    ESP_LOGI(TAG, "Returning OPTIGA public key (%d bytes, offset: %d)",
             optiga_public_key_len, optiga_public_key_offset);
    return 0;
}

#ifdef MBEDTLS_ECDH_GEN_PUBLIC_ALT
int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp,
                            mbedtls_mpi *d,
                            mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    (void)d; (void)f_rng; (void)p_rng;

    optiga_crypt_t *me = NULL;
    optiga_key_id_t key_oid = OPTIGA_TRUSTM_KEYOID;
    uint8_t pubbuf[512];
    uint16_t publen = sizeof(pubbuf);
    uint8_t public_offset = 3;

    if (!grp || !Q) return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* Support more curves for TLS compatibility */
    switch (grp->id) {
        case MBEDTLS_ECP_DP_SECP256R1:
            // This is fine, OPTIGA supports it
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
        case MBEDTLS_ECP_DP_SECP521R1:
        case MBEDTLS_ECP_DP_BP256R1:
        case MBEDTLS_ECP_DP_BP384R1:
        case MBEDTLS_ECP_DP_BP512R1:
            // These might be used by TLS, fall back to software
            ESP_LOGW(TAG, "Curve %d requested, using software fallback", grp->id);
            return mbedtls_ecdh_gen_public(grp, d, Q, f_rng, p_rng);
        default:
            ESP_LOGE(TAG, "Unsupported curve: %d", grp->id);
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    me = optiga_crypt_create(0, optiga_crypt_event_completed, NULL);
    if (!me) {
        ESP_LOGE(TAG, "optiga_crypt_create failed");
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    optiga_crypt_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t rc = optiga_crypt_ecc_generate_keypair(
        me,
        OPTIGA_ECC_CURVE_NIST_P_256,
        (optiga_key_usage_t)(OPTIGA_KEY_USAGE_KEY_AGREEMENT | OPTIGA_KEY_USAGE_AUTHENTICATION),
        FALSE,
        &key_oid,
        pubbuf,
        &publen
    );

    if (rc != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "invoke generate_keypair failed 0x%04X", rc);
        optiga_crypt_destroy(me);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    while (optiga_crypt_status == OPTIGA_LIB_BUSY) pal_os_timer_delay_in_milliseconds(5);
    if (optiga_crypt_status != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "generate_keypair callback failed 0x%04X", optiga_crypt_status);
        optiga_crypt_destroy(me);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (publen <= public_offset) {
        optiga_crypt_destroy(me);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    // Store the public key for CSR generation
    memcpy(optiga_public_key, pubbuf, publen);
    optiga_public_key_len = publen;
    optiga_public_key_offset = public_offset;

    ESP_LOGI(TAG, "Stored OPTIGA public key (%d bytes)", publen);

    if (mbedtls_ecp_point_read_binary(grp, Q, &pubbuf[public_offset], (size_t)(publen - public_offset)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_point_read_binary failed");
        optiga_crypt_destroy(me);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    optiga_crypt_destroy(me);
    return 0;
}
#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#ifdef MBEDTLS_ECDH_COMPUTE_SHARED_ALT
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp,
                                mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q,
                                const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    (void)d; (void)f_rng; (void)p_rng;


    if (!grp || !z || !Q) return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* Support more curves for TLS compatibility */
    switch (grp->id) {
        case MBEDTLS_ECP_DP_SECP256R1:
            // This is fine, OPTIGA supports it
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
        case MBEDTLS_ECP_DP_SECP521R1:
        case MBEDTLS_ECP_DP_BP256R1:
        case MBEDTLS_ECP_DP_BP384R1:
        case MBEDTLS_ECP_DP_BP512R1:
            // These might be used by TLS, fall back to software
            ESP_LOGW(TAG, "Curve %d requested, using software fallback", grp->id);
            return mbedtls_ecdh_compute_shared(grp, z, Q, d, f_rng, p_rng);
        default:
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    public_key_from_host_t pk;

    uint8_t pk_out[200];
    size_t pk_size = 0;
    uint8_t public_offset = 3; /* default for P-256 */

    /* We must create the same format as optiga expects. The snippet earlier used:
       pk_out[0] = 0x03;  pk_out[public_offset - 2] = 0x42 ; etc
       For simplicity here we create the octet string payload with 0x04 + X||Y
    */

    /* Write Q into binary uncompressed form (0x04 | X | Y) */
    if (mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                           &pk_size, pk_out + public_offset, sizeof(pk_out) - public_offset) != 0) {
            ESP_LOGE(TAG, "mbedtls_ecp_point_write_binary failed");
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    /* Build ASN.1 BIT STRING: tag, length, unused bits, then octet string (0x04|X|Y) */
        pk_out[0] = 0x03;                       /* BIT STRING tag */
        /* length: number of bytes after the length byte = unused_bits(1) + point bytes(pk_size) */
        if (pk_size + 1 > 0xFF) {
            ESP_LOGE(TAG, "point too large");
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
        pk_out[1] = (uint8_t)(1 + pk_size);     /* length */
        pk_out[2] = 0x00;                       /* unused bits */

        /* Debug print of the built public key (optional) */
        ESP_LOGI(TAG, "pk_out total len=%u", (unsigned)(public_offset + pk_size));
        // for (size_t i = 0; i < public_offset + pk_size; ++i) ESP_LOGI(TAG, "%02X", pk_out[i]);

        /* Fill public_key_from_host_t */
        pk.public_key = pk_out;
        pk.length = (uint16_t)(public_offset + pk_size);
        pk.key_type = OPTIGA_ECC_CURVE_NIST_P_256;

    /* call optiga_crypt_ecdh */
    optiga_crypt_t *me = optiga_crypt_create(0, optiga_crypt_event_completed, NULL);
    if (!me) {
        ESP_LOGE(TAG, "optiga_crypt_create failed");
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    uint8_t shared_buf[MBEDTLS_ECP_MAX_BYTES];
    memset(shared_buf, 0, sizeof(shared_buf));

    optiga_crypt_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t rc = optiga_crypt_ecdh(me, OPTIGA_TRUSTM_KEYOID, &pk, 1, shared_buf);
    if (rc != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "invoke optiga_crypt_ecdh failed: 0x%04X", rc);
        optiga_crypt_destroy(me);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    while (optiga_crypt_status == OPTIGA_LIB_BUSY) pal_os_timer_delay_in_milliseconds(5);
    if (optiga_crypt_status != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "optiga_crypt_ecdh callback failed 0x%04X", optiga_crypt_status);
        optiga_crypt_destroy(me);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* Read shared into z (assume X coordinate length = size of prime) */
    size_t zlen = mbedtls_mpi_size(&grp->P);
    if (mbedtls_mpi_read_binary(z, shared_buf, zlen) != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_read_binary failed");
        optiga_crypt_destroy(me);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    optiga_crypt_destroy(me);
    return 0;
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

/* ---------- End ALT functions ---------- */
