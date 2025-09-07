/* main/mbedtls_user_config.h
 * Force mbedTLS to use your alternate ECDH hooks.
 */

#ifndef MBEDTLS_USER_CONFIG_H
#define MBEDTLS_USER_CONFIG_H

/* Enable the necessary ECC curves */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED

/* Use the alternate ECDH/ECDSA implementations */
#define MBEDTLS_ECDH_GEN_PUBLIC_ALT
#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT
#define MBEDTLS_ECDSA_SIGN_ALT
#define MBEDTLS_ECDSA_VERIFY_ALT
#define MBEDTLS_ECDSA_GENKEY_ALT

/* Enable PK features needed for CSR generation */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_X509_CSR_WRITE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C

/* Enable specific algorithms */
#define MBEDTLS_SHA256_C
#define MBEDTLS_ASN1_PARSE_C

/* Include the rest of mbedTLS defaults */
#include "../external/mbedtls/include/mbedtls/config.h"

#endif /* MBEDTLS_USER_CONFIG_H */
