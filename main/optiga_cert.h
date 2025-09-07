#ifndef OPTIGA_CERT_H
#define OPTIGA_CERT_H

#include <stddef.h>
#include <stdint.h>
#include "mbedtls/x509_csr.h"

#ifdef __cplusplus
extern "C" {
#endif

int optiga_get_public_key(uint8_t **public_key, size_t *public_key_len, uint8_t *offset);
int optiga_sign_data(const uint8_t *data_to_sign, size_t data_len, uint8_t *signature, size_t *sig_len);
int generate_csr_with_optiga(const char *common_name, uint8_t *pem_buffer, size_t pem_size);
int optiga_custom_sign(void *ctx, unsigned char *hash, size_t hash_len,
                       unsigned char *sig, size_t *sig_len);

#ifdef __cplusplus
}
#endif

#endif /* OPTIGA_CERT_H */
