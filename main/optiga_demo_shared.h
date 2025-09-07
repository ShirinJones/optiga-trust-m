#pragma once

/* include the header that defines optiga types */
#include "optiga_util.h"     /* optiga_util_t, optiga_util_create, ... */
#include "optiga_lib_types.h" /* optiga_lib_status_t, OPTIGA_* enums etc */
#include <stdbool.h>

/* Key OID for demo */
#define OPTIGA_TRUSTM_KEYOID 0xE103

/* Fallback if not defined in headers */
#ifndef OPTIGA_LIB_ERROR
  #ifdef OPTIGA_CMD_ERROR
    #define OPTIGA_LIB_ERROR OPTIGA_CMD_ERROR
  #else
    #define OPTIGA_LIB_ERROR ((optiga_lib_status_t)0xFFFFU)
  #endif
#endif

#ifndef PAL_STATUS_SUCCESS
  #define PAL_STATUS_SUCCESS 0
#endif

/* Extern variables (defined in main.c) */
extern volatile optiga_lib_status_t optiga_app_status;
extern volatile optiga_lib_status_t optiga_crypt_status;
/* now the type is known */
extern optiga_util_t *me_util;

int optiga_init(void);
const uint8_t *optiga_get_ca_cert(void);
bool is_optiga_initialized(void);
void start_mqtt_demo(void);

