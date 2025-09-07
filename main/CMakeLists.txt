idf_component_register(
    SRCS
    	optiga_ecdsa_alt.c
        optiga_ecdh_alt.c
        main.c
        mqtt_optiga_demo.c
    	optiga_cert.c
        
        
        ../src/cmd/optiga_cmd.c
        ../src/common/optiga_lib_common.c
        ../src/common/optiga_lib_logger.c
        ../src/comms/ifx_i2c/ifx_i2c_config.c
        ../src/comms/ifx_i2c/ifx_i2c_data_link_layer.c
        ../src/comms/ifx_i2c/ifx_i2c_physical_layer.c
        ../src/comms/ifx_i2c/ifx_i2c_presentation_layer.c
        ../src/comms/ifx_i2c/ifx_i2c_transport_layer.c
        ../src/comms/ifx_i2c/ifx_i2c.c
        ../src/comms/optiga_comms_ifx_i2c.c
        ../src/crypt/optiga_crypt.c
        ../src/util/optiga_util.c

        # PAL
        ../extras/pal/esp32_freertos/pal.c
        ../extras/pal/esp32_freertos/pal_gpio.c
        ../extras/pal/esp32_freertos/pal_i2c.c
        ../extras/pal/esp32_freertos/pal_ifx_i2c_config.c
        ../extras/pal/esp32_freertos/pal_logger.c
        ../extras/pal/esp32_freertos/pal_os_datastore.c
        ../extras/pal/esp32_freertos/pal_os_event.c
        ../extras/pal/esp32_freertos/pal_os_lock.c
        ../extras/pal/esp32_freertos/pal_os_memory.c
        ../extras/pal/esp32_freertos/pal_os_timer.c
        ../extras/pal/pal_crypt_mbedtls.c
        
    INCLUDE_DIRS
        ../include
        ../external/mbedtls/include
        ../include/cmd
        ../include/common
        ../include/comms
        ../include/ifx_i2c
        ../include/pal
        
    PRIV_REQUIRES mbedtls
        
    REQUIRES
        mbedtls
        driver 
        esp_event
        freertos
        esp_timer
        esp_wifi
        log
        json
        esp-tls 
		esp_http_client 
		esp_https_ota 
		esp_https_server 
		nvs_flash 
		spi_flash 
		mqtt 
		esp_netif 
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    MBEDTLS_ECDSA_SIGN_ALT
    MBEDTLS_ECDSA_VERIFY_ALT
    MBEDTLS_ECDSA_GENKEY_ALT
    MBEDTLS_ECDH_GEN_PUBLIC_ALT
    MBEDTLS_ECDH_COMPUTE_SHARED_ALT
)

add_compile_definitions(CONFIG_OPTIGA_TRUST_M_PRIVKEY_SLOT=0xE0F1)

# (Optional) extra warnings; many are already set by IDF
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall -Wextra
)
