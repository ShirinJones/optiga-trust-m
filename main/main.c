/* main.c - demo using OPTIGA-backed ECDH via mbedTLS ALT hooks
 *
 * Build: make sure to define MBEDTLS_USER_CONFIG_FILE and
 * MBEDTLS_ECDH_GEN_PUBLIC_ALT MBEDTLS_ECDH_COMPUTE_SHARED_ALT in CMakeLists
 *
 * Notes:
 * - This example focuses on NIST P-256 (SECP256R1) for simplicity.
 * - Error handling is compact to keep the example readable.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>

#include "esp_task_wdt.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"

#include "driver/i2c.h"
#include "driver/gpio.h"
#include "driver/uart.h"

#include "optiga_crypt.h"
#include "optiga_util.h"
#include "common/optiga_lib_logger.h"

#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/x509_csr.h"

#include "pal/pal.h"
#include "pal/pal_i2c.h"
#include "pal/pal_gpio.h"
#include "pal/pal_ifx_i2c_config.h"
#include "pal/pal_os_event.h"
#include "pal_os_timer.h"

#include "optiga_cert.h"
#include "optiga_demo_shared.h"

/* OPTIGA_LIB_ERROR isn't provided by the platform headers, define a fallback.*/
#ifndef OPTIGA_LIB_ERROR
  #ifdef OPTIGA_CMD_ERROR
    #define OPTIGA_LIB_ERROR OPTIGA_CMD_ERROR
  #else
    /* Fallback value: non-zero error code */
    #define OPTIGA_LIB_ERROR ((optiga_lib_status_t)0xFFFFU)
  #endif
#endif

/* PAL status fallback (some PAL headers define PAL_STATUS_SUCCESS elsewhere).
   If not available, define a reasonable default. */
#ifndef PAL_STATUS_SUCCESS
  #define PAL_STATUS_SUCCESS 0
#endif


static const char *TAG = "OPTIGA_ECDH_DEMO";

/* hardware pins - adapt to your board */
#define I2C_NUM         I2C_NUM_0
#define SDA_PIN         21
#define SCL_PIN         22
#define RST_PIN         19
#define I2C_FREQ        400000


/* OPTIGA callback statuses (used by wrappers) */
volatile optiga_lib_status_t optiga_app_status = OPTIGA_LIB_ERROR;
volatile optiga_lib_status_t optiga_crypt_status = OPTIGA_LIB_ERROR;

/* OPTIGA utility handle */
optiga_util_t *me_util = NULL;

/* Global variable to track OPTIGA initialization status */
static bool optiga_initialized = false;

/* CA certificate for Mosquitto broker */
static const char ca_pem[] =
		"-----BEGIN CERTIFICATE-----\n"
		"MIICLzCCAdWgAwIBAgIUTFLsTHcD6zXvQrri2XaDvqiCf40wCgYIKoZIzj0EAwIw\n"
		"bTELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRMwEQYDVQQHDApCRU5HQUxVUlUg\n"
		"MQ0wCwYDVQQKDARDREFDMRIwEAYDVQQLDAlDREFDIEJMUiAxGTAXBgNVBAMMEENE\n"
		"QUMgRUNDIFJPT1QgQ0EwHhcNMjUwMTIxMTA1OTUzWhcNMzUwMTE5MTA1OTUzWjBt\n"
		"MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExEzARBgNVBAcMCkJFTkdBTFVSVSAx\n"
		"DTALBgNVBAoMBENEQUMxEjAQBgNVBAsMCUNEQUMgQkxSIDEZMBcGA1UEAwwQQ0RB\n"
		"QyBFQ0MgUk9PVCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGRsBNV6bYS2\n"
		"U62UdNa6FN53NkoVs/8ne6JbMHuA8+l6Pu+pGBxVKma6dvxe6k0XBW0IaXz3ZSSM\n"
		"N3PIZ0K/i6ijUzBRMB0GA1UdDgQWBBQsrtu7SpHVReDrod6ErDd1Sebh+jAfBgNV\n"
		"HSMEGDAWgBQsrtu7SpHVReDrod6ErDd1Sebh+jAPBgNVHRMBAf8EBTADAQH/MAoG\n"
		"CCqGSM49BAMCA0gAMEUCIDbUYabIZ0IpxrPC+nrkEgxlrxUptOXr34vwIeHB1Il5\n"
		"AiEAmU2lJJBQCM9resQV7AOs8uxMdf0NlrzWnKS3+CgZ8dE=\n"
		"-----END CERTIFICATE-----\n"
		"-----BEGIN CERTIFICATE-----\n"
		"MIICSTCCAe+gAwIBAgIUK5MfROuM4vcNZZErPbi3FBewf+cwCgYIKoZIzj0EAwIw\n"
		"bTELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRMwEQYDVQQHDApCRU5HQUxVUlUg\n"
		"MQ0wCwYDVQQKDARDREFDMRIwEAYDVQQLDAlDREFDIEJMUiAxGTAXBgNVBAMMEENE\n"
		"QUMgRUNDIFJPT1QgQ0EwHhcNMjUwMTIxMTExMTMwWhcNMjcxMDE4MTExMTMwWjB0\n"
		"MQswCQYDVQQGEwJJTjELMAkGA1UECAwCS0ExDDAKBgNVBAcMA0JMUjERMA8GA1UE\n"
		"CgwIQ0RBQyBCTFIxFzAVBgNVBAsMDkNEQUMgQkxSIERST05FMR4wHAYDVQQDDBVE\n"
		"Uk9ORSBJTlRFUk1FRElBVEUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAART\n"
		"pGfl8zZvafG9btMGaydbQ42SYM5cSDEHV/jcpldS0R1IwYKesVxz66jXydh1WFuk\n"
		"2CtHwrYHitnEUExv2qVKo2YwZDAdBgNVHQ4EFgQU7Yy06OTDPnvmogQidvUUQBoE\n"
		"cW8wHwYDVR0jBBgwFoAULK7bu0qR1UXg66HehKw3dUnm4fowEgYDVR0TAQH/BAgw\n"
		"BgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIgaOHwPssR\n"
		"YRSwPYyscKFvVnvfm62+vj5I0I+Ms2tmq0ICIQCf84LWfSmHmtpjwkQ8dIfVY2TE\n"
		"hMNHH16+YevhZSAJaQ==\n"
		"-----END CERTIFICATE-----\n";

/* callbacks */
static void optiga_lib_callback(void *context, optiga_lib_status_t status) {
    (void)context;
    optiga_app_status = status;
    ESP_LOGI(TAG, "optiga_util callback: 0x%04X", status);

    if (status == OPTIGA_LIB_SUCCESS) {
        optiga_initialized = true;
        ESP_LOGI(TAG, "OPTIGA app opened successfully");
    }
}
void optiga_crypt_event_completed(void *context, optiga_lib_status_t status) {
    (void)context;
    optiga_crypt_status = status;
    ESP_LOGI(TAG, "optiga_crypt callback: 0x%04X", status);
}

/* init I2C (ESP-IDF style) */
static esp_err_t init_i2c(void) {
    i2c_driver_delete(I2C_NUM);

    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = SDA_PIN,
        .scl_io_num = SCL_PIN,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = I2C_FREQ
    };

    ESP_ERROR_CHECK(i2c_param_config(I2C_NUM, &conf));
    return i2c_driver_install(I2C_NUM, conf.mode, 0, 0, 0);
}

static void trustm_reset(void) {
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << RST_PIN,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&cfg);
    gpio_set_level(RST_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(RST_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(50));
}

/* Initialize optiga util and open application */
static int optiga_init_app(void) {
    if (!me_util) {
        me_util = optiga_util_create(0, optiga_lib_callback, NULL);
        if (!me_util) {
            ESP_LOGE(TAG, "optiga_util_create failed");
            return -1;
        }
    }

    optiga_app_status = OPTIGA_LIB_BUSY;
    optiga_lib_status_t ret = optiga_util_open_application(me_util, 0);
    if (ret != OPTIGA_LIB_SUCCESS) {
        ESP_LOGE(TAG, "open_application invoke failed: 0x%04X", ret);
        return -1;
    }

    // NON-BLOCKING: Return immediately and let the callback handle completion
    ESP_LOGI(TAG, "OPTIGA app open initiated (non-blocking)");
    return 0;
}

/* small helper to print hex */
static void print_hex(const char *label, const uint8_t *p, size_t len) {
    printf("%s (%u bytes):\n", label, (unsigned)len);
    for (size_t i=0;i<len;i++) {
        printf("%02X", p[i]);
        if ((i+1)%32==0) printf("\n");
    }
    printf("\n");
}

static void csr_generation_task(void *pvParameters) {
    int ret;
    char *common_name = (char *)pvParameters;

    ESP_LOGI(TAG, "Generating CSR using OPTIGA public key...");
    ESP_LOGI(TAG, "Free heap at task start: %" PRIu32 " bytes", esp_get_free_heap_size());

    // Generate complete binary CSR
    uint8_t csr_buffer[1024];
    size_t csr_len = 0;

    ESP_LOGI(TAG, "Free heap before CSR generation: %" PRIu32 " bytes", esp_get_free_heap_size());

    ret = generate_csr_with_optiga(common_name, (uint8_t *)csr_buffer, sizeof(csr_buffer));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to generate CSR: -0x%04X", -ret);
        ESP_LOGI(TAG, "Free heap after CSR failure: %" PRIu32 " bytes", esp_get_free_heap_size());
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Free heap after CSR generation: %" PRIu32 " bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "Complete CSR generated successfully (%d bytes)", csr_len);

    vTaskDelete(NULL);
}

static int generate_and_display_csr(void) {
    // Create a task with larger stack for CSR generation
    if (xTaskCreate(csr_generation_task, "csr_task", 12288, "esp32-optiga-client", 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create CSR task");
        return -1;
    }

    // Wait a bit for the task to complete
    vTaskDelay(pdMS_TO_TICKS(2000));  // Increased delay to 2 seconds
    return 0;
}

/* Demonstration procedure */
static int ecdh_demo(void) {
    int ret = 1;
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi d_host, z_optiga, z_host, d_dummy;
    mbedtls_ecp_point Q_optiga, Q_host, R;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "optiga_ecdh_demo";

    mbedtls_mpi_init(&d_host);
    mbedtls_mpi_init(&z_optiga);
    mbedtls_mpi_init(&z_host);
    mbedtls_mpi_init(&d_dummy);
    mbedtls_ecp_point_init(&Q_optiga);
    mbedtls_ecp_point_init(&Q_host);
    mbedtls_ecp_point_init(&R);

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)pers, strlen(pers)) != 0) {
        ESP_LOGE(TAG, "ctr_drbg_seed failed");
        goto cleanup;
    }

    /* load group (P-256) */
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        ESP_LOGE(TAG, "ecp_group_load failed");
        goto cleanup;
    }

    /* 1) Ask OPTIGA to generate keypair and return public point (this calls your ALT wrapper) */
    if (mbedtls_ecdh_gen_public(&grp, &d_dummy, &Q_optiga, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        ESP_LOGE(TAG, "mbedtls_ecdh_gen_public (OPTIGA) failed");
        goto cleanup;
    }

    /* Export OPTIGA public for printing */
    uint8_t opt_pubbin[200];
    size_t opt_pubbin_len = sizeof(opt_pubbin);
    if (mbedtls_ecp_point_write_binary(&grp, &Q_optiga, MBEDTLS_ECP_PF_UNCOMPRESSED, &opt_pubbin_len, opt_pubbin, sizeof(opt_pubbin)) != 0) {
        ESP_LOGE(TAG, "write_binary opt pub failed");
        goto cleanup;
    }
    print_hex("OPTIGA public (uncompressed)", opt_pubbin, opt_pubbin_len);

    /* 2) Generate a software ECDH keypair (the peer) */
    if (mbedtls_ecp_gen_keypair(&grp, &d_host, &Q_host, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        ESP_LOGE(TAG, "ecp_gen_keypair (host) failed");
        goto cleanup;
    }
    uint8_t host_pubbin[200];
    size_t host_pubbin_len = sizeof(host_pubbin);
    if (mbedtls_ecp_point_write_binary(&grp, &Q_host, MBEDTLS_ECP_PF_UNCOMPRESSED, &host_pubbin_len, host_pubbin, sizeof(host_pubbin)) != 0) {
        ESP_LOGE(TAG, "write_binary host pub failed");
        goto cleanup;
    }
    print_hex("Host public (uncompressed)", host_pubbin, host_pubbin_len);

    /* 3) Compute shared on host: z_host = d_host * Q_optiga */
    if (mbedtls_ecp_mul(&grp, &R, &d_host, &Q_optiga, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        ESP_LOGE(TAG, "ecp_mul host failed");
        goto cleanup;
    }
    size_t zlen = mbedtls_mpi_size(&grp.P);
    uint8_t zhostbuf[MBEDTLS_ECP_MAX_BYTES];
    memset(zhostbuf, 0, sizeof(zhostbuf));
    if (mbedtls_mpi_write_binary(&R.X, zhostbuf, zlen) != 0) {
        ESP_LOGE(TAG, "mpi_write z_host failed");
        goto cleanup;
    }
    print_hex("z_host (X coordinate)", zhostbuf, zlen);

    /* 4) Ask OPTIGA to compute shared with our host public Q_host: z_optiga = OPTIGA_private * Q_host */
    if (mbedtls_ecdh_compute_shared(&grp, &z_optiga, &Q_host, &d_dummy, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        ESP_LOGE(TAG, "mbedtls_ecdh_compute_shared (OPTIGA) failed");
        goto cleanup;
    }
    uint8_t zoptbuf[MBEDTLS_ECP_MAX_BYTES];
    memset(zoptbuf, 0, sizeof(zoptbuf));
    if (mbedtls_mpi_write_binary(&z_optiga, zoptbuf, zlen) != 0) {
        ESP_LOGE(TAG, "mpi_write z_optiga failed");
        goto cleanup;
    }
    print_hex("z_optiga (from OPTIGA)", zoptbuf, zlen);

    /* 5) Compare */
    if (memcmp(zhostbuf, zoptbuf, zlen) == 0) {
        printf("SUCCESS: shared secrets match!\n");
    } else {
        printf("FAIL: shared secrets differ!\n");
    }

    ret = 0;

cleanup:
    mbedtls_ecp_point_free(&Q_optiga);
    mbedtls_ecp_point_free(&Q_host);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&d_host);
    mbedtls_mpi_free(&d_dummy);
    mbedtls_mpi_free(&z_host);
    mbedtls_mpi_free(&z_optiga);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

/* Demonstration procedure for ECDSA with OPTIGA ALT hooks */
static int ecdsa_demo(void)
{
    int ret = 1;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_mpi r, s;

    // Zero-initialize contexts FIRST
    memset(&ctx_sign, 0, sizeof(ctx_sign));
    memset(&ctx_verify, 0, sizeof(ctx_verify));
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "optiga_ecdsa_demo";

    unsigned char hash[32];   /* SHA-256 output */
    unsigned char sig[200];
    size_t sig_len = 0;

    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        ESP_LOGE(TAG, "ctr_drbg_seed failed: -0x%04X", -ret);
        goto cleanup;
    }

    /* ----------------------------------------------------------------
     * 1) Generate a keypair inside OPTIGA using ALT hook
     * ---------------------------------------------------------------- */
    ESP_LOGI(TAG, "Generating ECDSA keypair inside OPTIGA...");
    if ((ret = mbedtls_ecdsa_genkey(&ctx_sign, MBEDTLS_ECP_DP_SECP256R1,
                                    mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        ESP_LOGE(TAG, "ecdsa_genkey failed: -0x%04X", -ret);
        goto cleanup;
    }

    /* Copy group/Q into verify context (public key only) */
    if ((ret = mbedtls_ecp_group_copy(&ctx_verify.grp, &ctx_sign.grp)) != 0 ||
        (ret = mbedtls_ecp_copy(&ctx_verify.Q, &ctx_sign.Q)) != 0) {
        ESP_LOGE(TAG, "copy pubkey failed");
        goto cleanup;
    }

    /* ----------------------------------------------------------------
     * 2) Hash some message to sign
     * ---------------------------------------------------------------- */
    const char message[] = "Hello from OPTIGA ECDSA demo";
    mbedtls_md_context_t sha_ctx;
    mbedtls_md_init(&sha_ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&sha_ctx, md_info, 0);
    mbedtls_md_starts(&sha_ctx);
    mbedtls_md_update(&sha_ctx, (const unsigned char *) message, strlen(message));
    mbedtls_md_finish(&sha_ctx, hash);
    mbedtls_md_free(&sha_ctx);

    print_hex("Message hash (SHA-256)", hash, sizeof(hash));

    /* ----------------------------------------------------------------
     * 3) Sign the hash using OPTIGA private key
     * ---------------------------------------------------------------- */
    ESP_LOGI(TAG, "Signing with OPTIGA...");
    if ((ret = mbedtls_ecdsa_sign(&ctx_sign.grp, &r, &s, &ctx_sign.d,
                                 hash, sizeof(hash),
                                 mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        ESP_LOGE(TAG, "ecdsa_sign failed: -0x%04X", -ret);
        goto cleanup;
    }
    print_hex("Signature (DER)", sig, sig_len);

    /* ----------------------------------------------------------------
     * 4) Verify the signature (done in software against Q)
     * ---------------------------------------------------------------- */
    /* Verify the signature */
       ESP_LOGI(TAG, "Verifying signature...");
       if ((ret = mbedtls_ecdsa_verify(&ctx_verify.grp, hash, sizeof(hash),
                                     &ctx_verify.Q, &r, &s)) != 0) {
           ESP_LOGE(TAG, "ecdsa_verify failed: -0x%04X", -ret);
           goto cleanup;
       }

       ESP_LOGI(TAG, "SUCCESS: ECDSA signature verified!");
       ret = 0;

cleanup:
    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_ecdsa_free(&ctx_verify);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}


/* Initialize OPTIGA (extracted from app_main) */
int optiga_init(void) {
    ESP_LOGI(TAG, "Initializing OPTIGA...");

    /* PAL OS events required by OPTIGA PAL layer */
    pal_os_event_t *g_pal_event = pal_os_event_create(NULL, NULL);
    if (g_pal_event == NULL) {
        ESP_LOGE(TAG, "pal_os_event_create failed");
        return -1;
    }

    /* init i2c and reset trustm */
    if (init_i2c() != ESP_OK) {
        ESP_LOGE(TAG, "init_i2c failed");
        return -1;
    }
    trustm_reset();

    /* initialize optiga app - NON-BLOCKING */
    if (optiga_init_app() != 0) {
        ESP_LOGE(TAG, "optiga init failed");
        return -1;
    }

    // Don't set initialized flag here - wait for callback
    ESP_LOGI(TAG, "OPTIGA initialization started (non-blocking)");
    return 0;
}

/* Return CA certificate for MQTT TLS connection */
const uint8_t *optiga_get_ca_cert(void) {
    return (const uint8_t *)ca_pem;
}

/* Check if OPTIGA is initialized */
bool is_optiga_initialized(void) {
    return optiga_initialized;
}

void app_main(void)
{
    ESP_LOGI(TAG, "Starting OPTIGA-mbedTLS ECDH demo");

    // Watchdog configuration structure
    esp_task_wdt_config_t twdt_config = {
        .timeout_ms = 30000,        // 30 second timeout
        .idle_core_mask = (1 << CONFIG_FREERTOS_NUMBER_OF_CORES) - 1,  // Watch all cores
        .trigger_panic = false,     // Don't trigger panic (set to true if you want reset on timeout)
    };

    // Initialize Task Watchdog Timer
    esp_err_t ret = esp_task_wdt_init(&twdt_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize TWDT: %s", esp_err_to_name(ret));
    }

    // Add current task to watchdog monitoring
    ret = esp_task_wdt_add(NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add current task to TWDT: %s", esp_err_to_name(ret));
    }

    // Initialize OPTIGA using the new function
    if (optiga_init() != 0) {
        ESP_LOGE(TAG, "OPTIGA initialization failed");
        return;
    }

    // Wait for OPTIGA initialization to complete with timeout
    int max_wait_time = 10000; // 10 seconds timeout
    int wait_time = 0;

    while (!is_optiga_initialized() && wait_time < max_wait_time) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_time += 100;
        esp_task_wdt_reset(); // Reset watchdog
    }

    if (!is_optiga_initialized()) {
        ESP_LOGE(TAG, "OPTIGA initialization timeout");
        return;
    }

    /* run demo */
    if (ecdh_demo() != 0) {
        ESP_LOGE(TAG, "ecdh_demo failed");
    } else {
        ESP_LOGI(TAG, "ecdh_demo succeeded");
    }

    if (ecdsa_demo() != 0) {
        ESP_LOGE(TAG, "ecdsa_demo failed");
    } else {
        ESP_LOGI(TAG, "ecdsa_demo succeeded");
    }

    // Generate and display CSR
    if (generate_and_display_csr() != 0) {
        ESP_LOGE(TAG, "CSR generation failed");
    } else {
        ESP_LOGI(TAG, "CSR generation succeeded");
    }

    /* cleanup if needed */
    if (me_util) {
        optiga_util_destroy(me_util);
        me_util = NULL;
    }

    // Start MQTT demo after OPTIGA demos are complete
    start_mqtt_demo();

    // Keep the device running
    while (1) {

    	esp_task_wdt_reset();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
