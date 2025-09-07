/**
 * SPDX-FileCopyrightText: 2019-2024 Infineon Technologies AG
 * SPDX-License-Identifier: MIT
 *
 * @{
 */

#include "mbedtls/config.h"
#include "optiga_demo_shared.h"

#if defined(MBEDTLS_ECDSA_C)

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "mbedtls/asn1write.h"
#include "mbedtls/ecdsa.h"
#include "esp_log.h"  // Add this for ESP_LOGE

#include "optiga_crypt.h"
#include "optiga_lib_common.h"
#include "optiga_util.h"
#include "pal_os_timer.h"

#define PRINT_SIGNATURE 0
#define PRINT_HASH 0
#define PRINT_PUBLICKEY 0

#ifndef CONFIG_OPTIGA_TRUST_M_PRIVKEY_SLOT
/* Default private-key OID slot on Trust M (16-bit). */
#define CONFIG_OPTIGA_TRUST_M_PRIVKEY_SLOT OPTIGA_KEY_ID_E0F2
#endif

#define TAG "OPTIGA_ECDSA_ALT"

/* Updated by the OPTIGA async callback. */
static volatile optiga_lib_status_t ecdsa_completed_status = 0;

/* OPTIGA async callback */
static void optiga_crypt_event_completed(void *context, optiga_lib_status_t return_status)
{
    (void)context;
    ecdsa_completed_status = return_status;
}

// SHA-256 implementation
static void sha256(const uint8_t *data, size_t data_len, uint8_t *hash)
{
    // SHA-256 constants
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Initial hash values
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // Pre-processing
    size_t original_len = data_len;
    size_t new_len = ((((original_len + 8) / 64) + 1) * 64) - 8;
    uint8_t *msg = (uint8_t *)calloc(new_len + 64, 1);
    memcpy(msg, data, original_len);
    msg[original_len] = 0x80;

    // Append length in bits
    uint64_t bit_len = original_len * 8;
    for (int i = 0; i < 8; i++) {
        msg[new_len + 7 - i] = (bit_len >> (i * 8)) & 0xFF;
    }

    // Process the message in successive 512-bit chunks
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t w[64];

        // Copy chunk into first 16 words w[0..15] of the message schedule array
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[offset + i*4] << 24) |
                   (msg[offset + i*4 + 1] << 16) |
                   (msg[offset + i*4 + 2] << 8) |
                   (msg[offset + i*4 + 3]);
        }

        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = (w[i-15] >> 7 | w[i-15] << 25) ^
                         (w[i-15] >> 18 | w[i-15] << 14) ^
                         (w[i-15] >> 3);
            uint32_t s1 = (w[i-2] >> 17 | w[i-2] << 15) ^
                         (w[i-2] >> 19 | w[i-2] << 13) ^
                         (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        // Initialize working variables to current hash value
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        // Compression function main loop
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Add the compressed chunk to the current hash value
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    free(msg);

    // Produce the final hash value (big-endian)
    for (int i = 0; i < 4; i++) {
        hash[i]      = (h0 >> (24 - i * 8)) & 0xFF;
        hash[i + 4]  = (h1 >> (24 - i * 8)) & 0xFF;
        hash[i + 8]  = (h2 >> (24 - i * 8)) & 0xFF;
        hash[i + 12] = (h3 >> (24 - i * 8)) & 0xFF;
        hash[i + 16] = (h4 >> (24 - i * 8)) & 0xFF;
        hash[i + 20] = (h5 >> (24 - i * 8)) & 0xFF;
        hash[i + 24] = (h6 >> (24 - i * 8)) & 0xFF;
        hash[i + 28] = (h7 >> (24 - i * 8)) & 0xFF;
    }
}

static void simple_sha256(const uint8_t *data, size_t data_len, uint8_t *hash)
{
    sha256(data, data_len, hash);
}

#if defined(MBEDTLS_ECDSA_SIGN_ALT)
int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp,
                        mbedtls_mpi *r,
                        mbedtls_mpi *s,
                        const mbedtls_mpi *d,
                        const unsigned char *buf,
                        size_t blen,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng )
{
    (void)grp; (void)d; (void)f_rng; (void)p_rng;


    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    uint8_t der_signature[150] = {0};
    uint16_t dslen = sizeof(der_signature);
    uint8_t *p = der_signature;
    const uint8_t *end = der_signature + dslen;
    uint8_t hashed_data[32];
    const uint8_t *data_to_sign = buf;
    size_t data_len = blen;

    optiga_crypt_t *me = NULL;
    optiga_lib_status_t st = OPTIGA_CRYPT_ERROR;

    /* If data is longer than 32 bytes, it's probably not a hash */
    if (blen > 32) {
        ESP_LOGW(TAG, "Data length %d > 32, hashing first", blen);

        // Use a simple software hash since OPTIGA hash function signature is different
        simple_sha256(buf, blen, hashed_data);

        // Use the hashed data for signing
        data_to_sign = hashed_data;
        data_len = sizeof(hashed_data);

        ESP_LOGI(TAG, "Hashed data to 32 bytes for signing");
        ESP_LOG_BUFFER_HEXDUMP(TAG, data_to_sign, data_len, ESP_LOG_DEBUG);
    }

    /* Initialize MPIs */
    mbedtls_mpi_init(r);
    mbedtls_mpi_init(s);

    ESP_LOGI(TAG, "Signing data (len=%d):", data_len);
    ESP_LOG_BUFFER_HEX(TAG, data_to_sign, data_len);

    me = optiga_crypt_create(0, optiga_crypt_event_completed, NULL);
    if (me == NULL)
    {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        goto cleanup;
    }

    /* Sign digest inside OPTIGA */
    ecdsa_completed_status = OPTIGA_LIB_BUSY;
    st = optiga_crypt_ecdsa_sign(me,
                                (unsigned char *)data_to_sign,
                                (uint8_t)data_len,
                                (uint16_t)CONFIG_OPTIGA_TRUST_M_PRIVKEY_SLOT,
                                der_signature,
                                &dslen);
    if (st != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "optiga_crypt_ecdsa_sign failed: 0x%04X", st);
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* Wait for completion */
    while (ecdsa_completed_status == OPTIGA_LIB_BUSY) {
        pal_os_timer_delay_in_milliseconds(10);
    }

    if (ecdsa_completed_status != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "optiga_crypt_ecdsa_sign completion failed: 0x%04X", ecdsa_completed_status);
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanup;
    }

    if (ecdsa_completed_status != OPTIGA_LIB_SUCCESS) {
            ESP_LOGE(TAG, "optiga_crypt_ecdsa_sign completion failed: 0x%04X", ecdsa_completed_status);

            // Map OPTIGA error codes to mbedTLS errors
            switch (ecdsa_completed_status) {
                case OPTIGA_CRYPT_ERROR:
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                case OPTIGA_DEVICE_ERROR:
                    ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
                    break;
                case OPTIGA_CMD_ERROR:
                    ret = MBEDTLS_ERR_ECP_INVALID_KEY;
                    break;
                default:
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            goto cleanup;
        }

    /* Log signature - using separate statements to avoid macro argument issue */
    ESP_LOGI(TAG, "Signature from OPTIGA:");
    ESP_LOG_BUFFER_HEX(TAG, der_signature, dslen);

    /* Parse DER (r,s) back into MPIs */
    p = der_signature;
    end = der_signature + dslen;

    if ((ret = mbedtls_asn1_get_mpi(&p, end, r)) != 0) {
        ESP_LOGE(TAG, "Failed to parse r from signature: -0x%04X", -ret);
        goto cleanup;
    }

    if ((ret = mbedtls_asn1_get_mpi(&p, end, s)) != 0) {
        ESP_LOGE(TAG, "Failed to parse s from signature: -0x%04X", -ret);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (me) {
        optiga_crypt_destroy(me);
    }

    if (ret != 0) {
        mbedtls_mpi_free(r);
        mbedtls_mpi_free(s);
    }

    return ret;
}
#endif /* MBEDTLS_ECDSA_SIGN_ALT */

#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf,
                          size_t blen,
                          const mbedtls_ecp_point *Q,
                          const mbedtls_mpi *r,
                          const mbedtls_mpi *s )
{

{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    optiga_lib_status_t st = OPTIGA_CRYPT_ERROR;

    public_key_from_host_t public_key;
    uint8_t public_key_out[150];
    uint8_t publickey_offset = 3;
    uint8_t signature[150];
    uint8_t *p = NULL;
    size_t signature_len = 0;
    size_t public_key_len = 0;
    uint8_t truncated_hash_length;

    optiga_crypt_t *me = NULL;

    /* Only Trust M supported curves */
    if (grp->id < MBEDTLS_ECP_DP_SECP256R1 || grp->id > MBEDTLS_ECP_DP_BP512R1)
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    public_key.key_type = OPTIGA_ECC_CURVE_NIST_P_256;
    truncated_hash_length = 32;
    if (grp->id == MBEDTLS_ECP_DP_SECP384R1) {
        public_key.key_type = OPTIGA_ECC_CURVE_NIST_P_384;
        truncated_hash_length = 48;
    } else if (grp->id == MBEDTLS_ECP_DP_SECP521R1) {
        public_key.key_type = OPTIGA_ECC_CURVE_NIST_P_521;
        truncated_hash_length = 64;
        publickey_offset = 4;
    } else if (grp->id == MBEDTLS_ECP_DP_BP256R1) {
        public_key.key_type = OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1;
        truncated_hash_length = 32;
    } else if (grp->id == MBEDTLS_ECP_DP_BP384R1) {
        public_key.key_type = OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1;
        truncated_hash_length = 48;
    } else if (grp->id == MBEDTLS_ECP_DP_BP512R1) {
        public_key.key_type = OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1;
        truncated_hash_length = 64;
        publickey_offset = 4;
    }

    /* Build DER signature (r,s) into the tail of buffer */
    memset(signature, 0x00, sizeof(signature));
    p = signature + sizeof(signature);
    signature_len  = mbedtls_asn1_write_mpi(&p, signature, s);
    signature_len += mbedtls_asn1_write_mpi(&p, signature, r);

#if (PRINT_SIGNATURE == 1)
    for (size_t x = 0; x < signature_len; )
    {
        printf("%.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X\r\n",
               p[x], p[x+1], p[x+2], p[x+3],
               p[x+4], p[x+5], p[x+6], p[x+7]);
        x += 8;
    }
#endif

    /* Export public key from mbedTLS point into OPTIGA host format */
    public_key.public_key = public_key_out;

    if (mbedtls_ecp_point_write_binary(grp, Q,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &public_key_len,
                                       &public_key_out[publickey_offset],
                                       sizeof(public_key_out)) != 0)
        goto cleanup;

    public_key_out[0] = 0x03; /* "public key" tag for OPTIGA format */
    public_key_out[publickey_offset - 2] = (uint8_t)(public_key_len + 1);
    public_key_out[publickey_offset - 1] = 0x00;

    if (publickey_offset == 4)
        public_key_out[1] = 0x81; /* length ext */

    public_key.length = (uint16_t)(public_key_len + publickey_offset);

#if (PRINT_PUBLICKEY == 1)
#define PUBK(a) public_key.public_key[a]
    for (int i = 0; i < public_key.length; )
    {
        printf("%.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X\r\n",
               PUBK(i), PUBK(i+1), PUBK(i+2), PUBK(i+3),
               PUBK(i+4), PUBK(i+5), PUBK(i+6), PUBK(i+7));
        i += 8;
        if (public_key.length - i < 8)
        {
            int x = public_key.length - i;
            while (x--) { printf("%.2X ", PUBK(i++)); }
            printf("\r\n");
        }
    }
#undef PUBK
#endif

    /* If hash is longer than curve order size, truncate */
    if (blen > truncated_hash_length)
        blen = truncated_hash_length;

    me = optiga_crypt_create(0, optiga_crypt_event_completed, NULL);
    if (me == NULL)
    {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        goto cleanup;
    }

    /* Verify inside OPTIGA */
    ecdsa_completed_status = OPTIGA_LIB_BUSY;
    st = optiga_crypt_ecdsa_verify(me,
                                   (uint8_t *)buf,
                                   (uint8_t)blen,
                                   (uint8_t *)p,
                                   (uint16_t)signature_len,
                                   OPTIGA_CRYPT_HOST_DATA,
                                   (void *)&public_key);
    if (st != OPTIGA_LIB_SUCCESS)
        goto cleanup;

    while (ecdsa_completed_status == OPTIGA_LIB_BUSY)
        pal_os_timer_delay_in_milliseconds(10);

    if (ecdsa_completed_status != OPTIGA_LIB_SUCCESS)
        goto cleanup;

    ret = 0;

cleanup:
    if (me) (void)optiga_crypt_destroy(me);
    if (ret != 0 && ret != MBEDTLS_ERR_ECP_BAD_INPUT_DATA)
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    return ret;
}
}
#endif /* MBEDTLS_ECDSA_VERIFY_ALT */

#if defined(MBEDTLS_ECDSA_GENKEY_ALT)
int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx,
                         mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng)
{
    (void)f_rng; (void)p_rng;


    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    optiga_lib_status_t st = OPTIGA_CRYPT_ERROR;
    uint8_t public_key[150];
    uint16_t public_key_len = sizeof(public_key);
    optiga_ecc_curve_t curve_id;
    uint16_t privkey_oid = CONFIG_OPTIGA_TRUST_M_PRIVKEY_SLOT;
    uint8_t pubkey_offset = 3; // Default for most curves

    optiga_crypt_t *me = optiga_crypt_create(0, optiga_crypt_event_completed, NULL);
    if (me == NULL) {
        ESP_LOGE(TAG, "optiga_crypt_create failed");
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    // Initialize the group first
    if ((ret = mbedtls_ecp_group_load(&ctx->grp, gid)) != 0) {
        ESP_LOGE(TAG, "ecp_group_load failed: -0x%04X", -ret);
        goto cleanup;
    }

    // Map mbedTLS group to OPTIGA curve id
    switch (gid) {
        case MBEDTLS_ECP_DP_SECP256R1:
            curve_id = OPTIGA_ECC_CURVE_NIST_P_256;
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
            curve_id = OPTIGA_ECC_CURVE_NIST_P_384;
            break;
        case MBEDTLS_ECP_DP_SECP521R1:
            curve_id = OPTIGA_ECC_CURVE_NIST_P_521;
            pubkey_offset = 4; // Different header size for 521-bit
            break;
        case MBEDTLS_ECP_DP_BP256R1:
            curve_id = OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1;
            break;
        case MBEDTLS_ECP_DP_BP384R1:
            curve_id = OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1;
            break;
        case MBEDTLS_ECP_DP_BP512R1:
            curve_id = OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1;
            pubkey_offset = 4;
            break;
        default:
            ESP_LOGE(TAG, "Unsupported curve: %d", gid);
            ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
            goto cleanup;
    }

    // Generate keypair inside OPTIGA
    ecdsa_completed_status = OPTIGA_LIB_BUSY;
    st = optiga_crypt_ecc_generate_keypair(me,
                                         curve_id,
                                         (optiga_key_usage_t)(OPTIGA_KEY_USAGE_SIGN | OPTIGA_KEY_USAGE_KEY_AGREEMENT),
                                         FALSE,
                                         &privkey_oid,
                                         public_key,
                                         &public_key_len);
    if (st != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "ecc_generate_keypair invoke failed: 0x%04X", st);
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    // Wait for completion
    while (ecdsa_completed_status == OPTIGA_LIB_BUSY) {
        pal_os_timer_delay_in_milliseconds(5);
    }

    if (ecdsa_completed_status != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "ecc_generate_keypair failed: 0x%04X", ecdsa_completed_status);
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    // Load public key (skip OPTIGA's header)
    if ((ret = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Q,
                                           public_key + pubkey_offset,
                                           public_key_len - pubkey_offset)) != 0) {
        ESP_LOGE(TAG, "ecp_point_read_binary failed: -0x%04X", -ret);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (me) {
        optiga_crypt_destroy(me);
    }
    // Ensure the context is properly initialized even on failure
    if (ret != 0) {
        mbedtls_ecp_group_free(&ctx->grp);
        mbedtls_ecp_point_init(&ctx->Q);
    }
    return ret;
}

#endif /* MBEDTLS_ECDSA_GENKEY_ALT */

#endif /* MBEDTLS_ECDSA_C */
/**
 * @}
 */
