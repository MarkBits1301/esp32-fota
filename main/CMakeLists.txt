idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES esp_wifi nvs_flash esp_event esp_netif esp_http_client esp_https_ota app_update mbedtls cjson esp_driver_gpio esp_http_server esp_timer)
