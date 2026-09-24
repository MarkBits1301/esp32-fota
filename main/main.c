#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "driver/gpio.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "cJSON.h"
#include "esp_http_server.h"

// DNS Hijacking Sockets
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"

// --- HARDWARE PIN DEFINITIONS ---
#define BOOT_BUTTON_GPIO    GPIO_NUM_0    // Hold 3s to factory wipe NVS
#define BLINK_GPIO          GPIO_NUM_2    // Onboard Blue Status LED
#define RELAY_1_GPIO        GPIO_NUM_23
#define RELAY_2_GPIO        GPIO_NUM_22
#define RELAY_3_GPIO        GPIO_NUM_21
#define RELAY_4_GPIO        GPIO_NUM_19

#define RELAY_ON            0
#define RELAY_OFF           1

// --- CLOUD CONFIGURATION ---
#define USER_UID            "fmFwYOeLHKboGYAhAEoPqemlU8u1"

static const char *TAG = "APP_CORE";
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static int64_t s_current_version = 0;
static char s_device_id[32] = {0};
static char s_ap_ssid[32] = {0};
static char s_db_url[256];
static char s_log_url[256];
static char s_device_ip[20] = "0.0.0.0";
static char s_reset_reason_str[64] = "Unknown";

static char s_active_ssid[33] = {0};
static char s_active_pass[65] = {0};
static bool s_is_provisioned = false;

static int s_relay_states[4] = {0, 0, 0, 0};
static const gpio_num_t s_relay_pins[4] = {RELAY_1_GPIO, RELAY_2_GPIO, RELAY_3_GPIO, RELAY_4_GPIO};

// ============================================================================
// 1. HARDWARE MAC IDENTIFICATION & RESET REASON
// ============================================================================
static void init_device_identity(void)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(s_device_id, sizeof(s_device_id), "esp32_%02X%02X%02X", mac[3], mac[4], mac[5]);
    snprintf(s_ap_ssid, sizeof(s_ap_ssid), "ESP32-%02X%02X", mac[4], mac[5]);

    snprintf(s_db_url, sizeof(s_db_url),
             "https://esp32-ota-pro-default-rtdb.asia-southeast1.firebasedatabase.app/users/%s/devices/%s.json",
             USER_UID, s_device_id);
    snprintf(s_log_url, sizeof(s_log_url),
             "https://esp32-ota-pro-default-rtdb.asia-southeast1.firebasedatabase.app/users/%s/devices/%s/logs.json",
             USER_UID, s_device_id);

    esp_reset_reason_t reason = esp_reset_reason();
    switch (reason) {
        case ESP_RST_POWERON:   strcpy(s_reset_reason_str, "Cold Power-On"); break;
        case ESP_RST_SW:        strcpy(s_reset_reason_str, "Software Reset / OTA"); break;
        case ESP_RST_PANIC:     strcpy(s_reset_reason_str, "Kernel Panic / Crash"); break;
        case ESP_RST_INT_WDT:   strcpy(s_reset_reason_str, "Interrupt Watchdog"); break;
        case ESP_RST_TASK_WDT:  strcpy(s_reset_reason_str, "Task Watchdog (TWDT)"); break;
        case ESP_RST_BROWNOUT:  strcpy(s_reset_reason_str, "Brownout (Voltage Sag)"); break;
        default:                snprintf(s_reset_reason_str, sizeof(s_reset_reason_str), "Code: %d", reason); break;
    }
}

// ============================================================================
// 2. NVS PERSISTENCE (WI-FI CREDENTIALS & RELAY STATES)
// ============================================================================
static void load_relay_states_from_nvs(void)
{
    nvs_handle_t nvs;
    if (nvs_open("hw_store", NVS_READONLY, &nvs) == ESP_OK) {
        uint8_t mask = 0;
        if (nvs_get_u8(nvs, "relays", &mask) == ESP_OK) {
            for (int i = 0; i < 4; i++) {
                s_relay_states[i] = (mask >> i) & 0x01;
            }
        }
        nvs_close(nvs);
    }
    // Apply states to physical GPIO lines immediately
    for (int i = 0; i < 4; i++) {
        gpio_set_level(s_relay_pins[i], s_relay_states[i] ? RELAY_ON : RELAY_OFF);
    }
}

static void save_relay_states_to_nvs(void)
{
    nvs_handle_t nvs;
    if (nvs_open("hw_store", NVS_READWRITE, &nvs) == ESP_OK) {
        uint8_t mask = 0;
        for (int i = 0; i < 4; i++) {
            if (s_relay_states[i]) mask |= (1 << i);
        }
        nvs_set_u8(nvs, "relays", mask);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
}

static bool load_stored_wifi(char *ssid, size_t ssid_len, char *pass, size_t pass_len)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("wifi_store", NVS_READONLY, &nvs);
    if (err != ESP_OK) return false;

    err = nvs_get_str(nvs, "ssid", ssid, &ssid_len);
    if (err == ESP_OK) {
        err = nvs_get_str(nvs, "pass", pass, &pass_len);
    }
    nvs_close(nvs);
    return (err == ESP_OK && strlen(ssid) > 0);
}

static void save_stored_wifi(const char *ssid, const char *pass)
{
    nvs_handle_t nvs;
    if (nvs_open("wifi_store", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_str(nvs, "ssid", ssid);
        nvs_set_str(nvs, "pass", pass);
        nvs_commit(nvs);
        nvs_close(nvs);
        ESP_LOGI(TAG, "Credentials saved to NVS.");
    }
}

void factory_reset_erase_nvs(void)
{
    ESP_LOGW(TAG, "Factory Reset Triggered! Erasing all NVS profiles...");
    nvs_handle_t nvs;
    if (nvs_open("wifi_store", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
    if (nvs_open("hw_store", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
    for (int i = 0; i < 6; i++) {
        gpio_set_level(BLINK_GPIO, i % 2);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    esp_restart();
}

static void factory_reset_button_task(void *pvParameters)
{
    gpio_set_direction(BOOT_BUTTON_GPIO, GPIO_MODE_INPUT);
    gpio_set_pull_mode(BOOT_BUTTON_GPIO, GPIO_PULLUP_ONLY);

    int hold_time_ms = 0;
    while (1) {
        if (gpio_get_level(BOOT_BUTTON_GPIO) == 0) {
            hold_time_ms += 100;
            if (hold_time_ms >= 3000) {
                factory_reset_erase_nvs();
            }
        } else {
            hold_time_ms = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

// ============================================================================
// 3. CAPTIVE DNS SERVER (Port 53)
// ============================================================================
static void dns_server_task(void *pvParameters)
{
    uint8_t rx[256], tx[256];
    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(53),
    };

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) { vTaskDelete(NULL); return; }
    if (bind(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) { close(sock); vTaskDelete(NULL); return; }

    while (1) {
        struct sockaddr_in cli;
        socklen_t len = sizeof(cli);
        int n = recvfrom(sock, rx, sizeof(rx), 0, (struct sockaddr *)&cli, &len);
        if (n < 12) continue;

        memcpy(tx, rx, n);
        tx[2] = 0x81; tx[3] = 0x80;
        tx[6] = 0x00; tx[7] = 0x01;
        tx[8] = 0x00; tx[9] = 0x00;
        tx[10] = 0x00; tx[11] = 0x00;

        int idx = n;
        tx[idx++] = 0xC0; tx[idx++] = 0x0C;
        tx[idx++] = 0x00; tx[idx++] = 0x01;
        tx[idx++] = 0x00; tx[idx++] = 0x01;
        tx[idx++] = 0x00; tx[idx++] = 0x00; tx[idx++] = 0x00; tx[idx++] = 0x3C;
        tx[idx++] = 0x00; tx[idx++] = 0x04;
        tx[idx++] = 192;  tx[idx++] = 168;  tx[idx++] = 4;   tx[idx++] = 1;

        sendto(sock, tx, idx, 0, (struct sockaddr *)&cli, len);
    }
}

// ============================================================================
// 4. ONBOARDING & RUNTIME HTML INTERFACES
// ============================================================================
static const char *SETUP_PORTAL_HTML =
"<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<title>Device Onboarding</title><style>"
"*{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,monospace;}"
"body{background:#0b0f19;color:#fff;padding:24px 16px;display:flex;flex-direction:column;align-items:center;min-height:100vh;}"
".box{background:#121a24;border:1px solid #1f2937;border-radius:14px;padding:24px;width:100%;max-width:400px;box-shadow:0 8px 24px rgba(0,0,0,0.6);}"
"h2{color:#00e5ff;font-size:20px;letter-spacing:1px;margin-bottom:6px;text-align:center;}"
"p{color:#8b949e;font-size:12px;margin-bottom:20px;text-align:center;line-height:1.4;}"
"label{font-size:11px;font-weight:bold;color:#8b949e;text-transform:uppercase;margin-bottom:6px;display:block;}"
"select,input{width:100%;padding:12px;margin-bottom:16px;background:#080c14;border:1px solid #30363d;border-radius:8px;color:#fff;font-size:14px;outline:none;}"
"select:focus,input:focus{border-color:#00e5ff;}"
"button{width:100%;padding:14px;background:#00e5ff;color:#0b0f19;border:none;border-radius:8px;font-size:14px;font-weight:bold;cursor:pointer;}"
"button:active{transform:scale(0.98);}"
".scan-btn{background:#1f2937;color:#00e5ff;padding:8px;font-size:12px;margin-bottom:14px;border:1px solid #30363d;}"
"</style></head><body>"
"<div class=\"box\">"
"<h2>DEVICE ONBOARDING</h2><p>Connect your appliance to Wi-Fi.</p>"
"<form action=\"/save\" method=\"POST\">"
"<label>Available Networks</label>"
"<select id=\"ssid-select\" name=\"ssid\" required><option value=\"\">Scanning nearby Wi-Fi...</option></select>"
"<button type=\"button\" class=\"scan-btn\" onclick=\"scanNetworks()\">Refresh Networks</button>"
"<label>Wi-Fi Password</label>"
"<input type=\"password\" name=\"pass\" placeholder=\"Network Password\">"
"<button type=\"submit\">CONNECT DEVICE</button>"
"</form></div>"
"<script>"
"async function scanNetworks(){"
"const s=document.getElementById('ssid-select');s.innerHTML='<option>Scanning...</option>';"
"try{"
"const res=await fetch('/scan');const list=await res.json();"
"s.innerHTML='';"
"if(list.length===0){s.innerHTML='<option value=\"\">No networks found</option>';return;}"
"list.forEach(n=>{"
"const opt=document.createElement('option');"
"opt.value=n.ssid;opt.innerText=n.ssid+' ('+n.rssi+' dBm)';"
"s.appendChild(opt);"
"});"
"}catch(e){s.innerHTML='<option value=\"\">Scan failed. Click refresh.</option>';}"
"}"
"window.onload=scanNetworks;"
"</script></body></html>";

static const char *SAVED_PAGE_HTML =
"<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<title>Saved</title><style>body{background:#0b0f19;color:#fff;font-family:monospace;padding:40px 16px;text-align:center;}h2{color:#38ef7d;margin-bottom:12px;}p{color:#8b949e;font-size:13px;}</style></head><body>"
"<h2>CONFIG COMMITTED</h2><p>Rebooting device and joining network...</p></body></html>";

static const char *INDEX_HTML =
"<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<title>ESP32 Mission Control</title><style>"
"*{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,monospace;}"
"body{background:#080c14;color:#fff;padding:24px 12px;display:flex;flex-direction:column;align-items:center;min-height:100vh;}"
"h2{color:#00e5ff;letter-spacing:1px;font-size:20px;text-align:center;}"
".sub{color:#8b949e;font-size:12px;margin-bottom:20px;text-align:center;}"
".container{width:100%;max-width:540px;display:flex;flex-direction:column;gap:16px;}"
".panel{background:rgba(18,26,36,0.9);border:1px solid #1f2937;border-radius:12px;padding:16px;box-shadow:0 4px 16px rgba(0,0,0,0.6);}"
".panel-title{color:#00e5ff;font-size:13px;font-weight:bold;letter-spacing:1px;margin-bottom:12px;border-bottom:1px solid #1f2937;padding-bottom:6px;}"
".metric-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;}"
".metric-box{background:#0d1420;border:1px solid #233044;border-radius:8px;padding:10px;}"
".metric-label{color:#8b949e;font-size:11px;text-transform:uppercase;margin-bottom:4px;}"
".metric-val{font-size:14px;font-weight:bold;color:#38ef7d;font-family:monospace;}"
".relay-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;}"
".card{background:#0d1420;border:1px solid #233044;border-radius:8px;padding:12px;text-align:center;transition:0.2s;}"
".card.active{border-color:#00e5ff;box-shadow:0 0 10px rgba(0,229,255,0.2);}"
".ch-name{font-size:12px;color:#8b949e;margin-bottom:6px;}"
".st{font-size:15px;font-weight:bold;margin-bottom:10px;color:#ff3b5c;}"
".card.active .st{color:#00e5ff;}"
"button{width:100%;padding:10px 0;border:none;border-radius:6px;font-size:12px;font-weight:bold;cursor:pointer;background:#1f2937;color:#8b949e;font-family:monospace;}"
".card.active button{background:#00e5ff;color:#0b0f19;}"
"</style></head><body>"
"<div class=\"container\">"
"<div><h2>ESP32 MISSION CONTROL</h2><p class=\"sub\" id=\"dev-title\">Loading Fleet Node...</p></div>"
"<div class=\"panel\">"
"<div class=\"panel-title\">LIVE SYSTEM OBSERVABILITY</div>"
"<div class=\"metric-grid\">"
"<div class=\"metric-box\"><div class=\"metric-label\">Boot Partition</div><div class=\"metric-val\" id=\"m-part\">---</div></div>"
"<div class=\"metric-box\"><div class=\"metric-label\">Wi-Fi Profile</div><div class=\"metric-val\" id=\"m-wsrc\" style=\"color:#38ef7d;\">---</div></div>"
"<div class=\"metric-box\"><div class=\"metric-label\">Free Heap / Min</div><div class=\"metric-val\" id=\"m-heap\">---</div></div>"
"<div class=\"metric-box\"><div class=\"metric-label\">Heap Frag.</div><div class=\"metric-val\" id=\"m-frag\">---</div></div>"
"<div class=\"metric-box\"><div class=\"metric-label\">Uptime</div><div class=\"metric-val\" id=\"m-up\">---</div></div>"
"<div class=\"metric-box\"><div class=\"metric-label\">Reset Reason</div><div class=\"metric-val\" id=\"m-rst\" style=\"font-size:12px;\">---</div></div>"
"</div>"
"</div>"
"<div class=\"panel\">"
"<div class=\"panel-title\">RELAY CONTROLLER (NVS PERSISTENT)</div>"
"<div class=\"relay-grid\">"
"<div class=\"card\" id=\"c0\"><div class=\"ch-name\">RELAY 1 (G23)</div><div class=\"st\" id=\"s0\">OFF</div><button onclick=\"toggle(1)\">SWITCH</button></div>"
"<div class=\"card\" id=\"c1\"><div class=\"ch-name\">RELAY 2 (G22)</div><div class=\"st\" id=\"s1\">OFF</div><button onclick=\"toggle(2)\">SWITCH</button></div>"
"<div class=\"card\" id=\"c2\"><div class=\"ch-name\">RELAY 3 (G21)</div><div class=\"st\" id=\"s2\">OFF</div><button onclick=\"toggle(3)\">SWITCH</button></div>"
"<div class=\"card\" id=\"c3\"><div class=\"ch-name\">RELAY 4 (G19)</div><div class=\"st\" id=\"s3\">OFF</div><button onclick=\"toggle(4)\">SWITCH</button></div>"
"</div>"
"</div>"
"</div>"
"<script>"
"async function poll(){"
"try{"
"const res=await fetch('/metrics');const d=await res.json();"
"document.getElementById('dev-title').innerText=d.device_id.toUpperCase()+' | Fleet Member';"
"document.getElementById('m-part').innerText=d.partition;"
"document.getElementById('m-wsrc').innerText='NVS: '+d.ssid;"
"document.getElementById('m-heap').innerText=(d.free_heap/1024).toFixed(1)+'k / '+(d.min_heap/1024).toFixed(1)+'k';"
"document.getElementById('m-frag').innerText=d.fragmentation+'%';"
"const u=d.uptime;const m=Math.floor(u/60);const s=u%60;"
"document.getElementById('m-up').innerText=m+'m '+s+'s';"
"document.getElementById('m-rst').innerText=d.reset_reason;"
"for(let i=0;i<4;i++){"
"const a=d.relays[i]===1;"
"document.getElementById('s'+i).innerText=a?'ACTIVE':'OFF';"
"document.getElementById('c'+i).className=a?'card active':'card';"
"}"
"}catch(e){}}"
"async function toggle(ch){await fetch('/r'+ch);poll();}"
"setInterval(poll,2000);poll();"
"</script></body></html>";

// ============================================================================
// 5. CLOUD DISPATCH & BACKGROUND SYNC
// ============================================================================
void cloud_print(const char *message)
{
    ESP_LOGI(TAG, "[CLOUD]: %s", message);
    char payload[256];
    snprintf(payload, sizeof(payload), "{\"msg\":\"%s\"}", message);

    esp_http_client_config_t config = {
        .url = s_log_url,
        .method = HTTP_METHOD_POST,
        .skip_cert_common_name_check = true,
        .timeout_ms = 8000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) return;
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, payload, strlen(payload));
    esp_http_client_perform(client);
    esp_http_client_cleanup(client);
}

// Push local state update to Firebase asynchronously
static void sync_relays_to_cloud(void)
{
    char patch_url[300];
    snprintf(patch_url, sizeof(patch_url),
             "https://esp32-ota-pro-default-rtdb.asia-southeast1.firebasedatabase.app/users/%s/devices/%s/relays.json",
             USER_UID, s_device_id);

    char payload[96];
    snprintf(payload, sizeof(payload),
             "{\"r1\":%d,\"r2\":%d,\"r3\":%d,\"r4\":%d}",
             s_relay_states[0], s_relay_states[1], s_relay_states[2], s_relay_states[3]);

    esp_http_client_config_t config = {
        .url = patch_url,
        .method = HTTP_METHOD_PUT,
        .skip_cert_common_name_check = true,
        .timeout_ms = 4000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client) {
        esp_http_client_set_header(client, "Content-Type", "application/json");
        esp_http_client_set_post_field(client, payload, strlen(payload));
        esp_http_client_perform(client);
        esp_http_client_cleanup(client);
    }
}

static void toggle_channel(int ch_idx)
{
    s_relay_states[ch_idx] = !s_relay_states[ch_idx];
    gpio_set_level(s_relay_pins[ch_idx], s_relay_states[ch_idx] ? RELAY_ON : RELAY_OFF);
    save_relay_states_to_nvs();
    sync_relays_to_cloud();
}

// ============================================================================
// 6. HTTP SERVER ROUTING
// ============================================================================
static esp_err_t portal_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, SETUP_PORTAL_HTML, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t captive_redirect_handler(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t scan_get_handler(httpd_req_t *req)
{
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 120,
        .scan_time.active.max = 250,
    };
    esp_wifi_scan_start(&scan_cfg, true);

    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);
    if (ap_count > 12) ap_count = 12;

    wifi_ap_record_t *ap_records = malloc(sizeof(wifi_ap_record_t) * ap_count);
    cJSON *root = cJSON_CreateArray();

    if (ap_records) {
        esp_wifi_scan_get_ap_records(&ap_count, ap_records);
        for (int i = 0; i < ap_count; i++) {
            if (strlen((char *)ap_records[i].ssid) == 0) continue;
            cJSON *item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, "ssid", (char *)ap_records[i].ssid);
            cJSON_AddNumberToObject(item, "rssi", ap_records[i].rssi);
            cJSON_AddItemToArray(root, item);
        }
        free(ap_records);
    }

    char *json_str = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_sendstr(req, json_str ? json_str : "[]");

    if (json_str) free(json_str);
    cJSON_Delete(root);
    return ESP_OK;
}

static void url_decode(char *dst, const char *src)
{
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit((int)a) && isxdigit((int)b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10); else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10); else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static esp_err_t portal_post_handler(httpd_req_t *req)
{
    char buf[256];
    int remaining = req->content_len;
    if (remaining >= sizeof(buf)) remaining = sizeof(buf) - 1;

    int ret = httpd_req_recv(req, buf, remaining);
    if (ret <= 0) return ESP_FAIL;
    buf[ret] = '\0';

    char raw_ssid[64] = {0}, raw_pass[64] = {0};
    char clean_ssid[33] = {0}, clean_pass[65] = {0};

    char *s = strstr(buf, "ssid=");
    if (s) {
        s += 5;
        char *amp = strchr(s, '&');
        if (amp) *amp = '\0';
        strncpy(raw_ssid, s, sizeof(raw_ssid) - 1);
        if (amp) {
            char *p = strstr(amp + 1, "pass=");
            if (p) {
                p += 5;
                strncpy(raw_pass, p, sizeof(raw_pass) - 1);
            }
        }
    }

    url_decode(clean_ssid, raw_ssid);
    url_decode(clean_pass, raw_pass);

    if (strlen(clean_ssid) > 0) {
        save_stored_wifi(clean_ssid, clean_pass);
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, SAVED_PAGE_HTML, HTTPD_RESP_USE_STRLEN);
        vTaskDelay(pdMS_TO_TICKS(1500));
        esp_restart();
    } else {
        httpd_resp_send_500(req);
    }
    return ESP_OK;
}

static esp_err_t index_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, INDEX_HTML, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t metrics_handler(httpd_req_t *req)
{
    uint32_t free_heap = esp_get_free_heap_size();
    uint32_t min_heap = esp_get_minimum_free_heap_size();
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    float frag = free_heap ? (1.0f - ((float)largest_block / (float)free_heap)) * 100.0f : 0.0f;

    wifi_ap_record_t ap_info;
    int8_t rssi = (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) ? ap_info.rssi : -127;

    const esp_partition_t *running = esp_ota_get_running_partition();
    const char *part_label = running ? running->label : "unknown";
    int64_t uptime_sec = esp_timer_get_time() / 1000000;

    char resp[384];
    snprintf(resp, sizeof(resp),
             "{\"device_id\":\"%s\",\"partition\":\"%s\",\"rssi\":%d,\"free_heap\":%lu,\"min_heap\":%lu,"
             "\"fragmentation\":%.1f,\"uptime\":%lld,\"reset_reason\":\"%s\","
             "\"ssid\":\"%s\",\"relays\":[%d,%d,%d,%d]}",
             s_device_id, part_label, rssi, (unsigned long)free_heap, (unsigned long)min_heap,
             frag, uptime_sec, s_reset_reason_str, s_active_ssid,
             s_relay_states[0], s_relay_states[1], s_relay_states[2], s_relay_states[3]);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_sendstr(req, resp);
    return ESP_OK;
}

static esp_err_t r1_handler(httpd_req_t *req) { toggle_channel(0); httpd_resp_sendstr(req, "OK"); return ESP_OK; }
static esp_err_t r2_handler(httpd_req_t *req) { toggle_channel(1); httpd_resp_sendstr(req, "OK"); return ESP_OK; }
static esp_err_t r3_handler(httpd_req_t *req) { toggle_channel(2); httpd_resp_sendstr(req, "OK"); return ESP_OK; }
static esp_err_t r4_handler(httpd_req_t *req) { toggle_channel(3); httpd_resp_sendstr(req, "OK"); return ESP_OK; }

static void start_provisioning_server(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 12;

    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t get_portal = { .uri = "/", .method = HTTP_GET, .handler = portal_get_handler };
        httpd_uri_t post_portal = { .uri = "/save", .method = HTTP_POST, .handler = portal_post_handler };
        httpd_uri_t scan_uri = { .uri = "/scan", .method = HTTP_GET, .handler = scan_get_handler };

        httpd_register_uri_handler(server, &get_portal);
        httpd_register_uri_handler(server, &post_portal);
        httpd_register_uri_handler(server, &scan_uri);

        httpd_uri_t u_ios = { .uri = "/hotspot-detect.html", .method = HTTP_GET, .handler = captive_redirect_handler };
        httpd_uri_t u_and = { .uri = "/generate_204", .method = HTTP_GET, .handler = captive_redirect_handler };
        httpd_uri_t u_win = { .uri = "/ncsi.txt", .method = HTTP_GET, .handler = captive_redirect_handler };

        httpd_register_uri_handler(server, &u_ios);
        httpd_register_uri_handler(server, &u_and);
        httpd_register_uri_handler(server, &u_win);
    }
}

static void start_runtime_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t u_get = { .uri = "/", .method = HTTP_GET, .handler = index_handler };
        httpd_uri_t u_met = { .uri = "/metrics", .method = HTTP_GET, .handler = metrics_handler };
        httpd_uri_t u1 = { .uri = "/r1", .method = HTTP_GET, .handler = r1_handler };
        httpd_uri_t u2 = { .uri = "/r2", .method = HTTP_GET, .handler = r2_handler };
        httpd_uri_t u3 = { .uri = "/r3", .method = HTTP_GET, .handler = r3_handler };
        httpd_uri_t u4 = { .uri = "/r4", .method = HTTP_GET, .handler = r4_handler };

        httpd_register_uri_handler(server, &u_get);
        httpd_register_uri_handler(server, &u_met);
        httpd_register_uri_handler(server, &u1);
        httpd_register_uri_handler(server, &u2);
        httpd_register_uri_handler(server, &u3);
        httpd_register_uri_handler(server, &u4);
    }
}

// ============================================================================
// 7. BACKGROUND FOTA & CLOUD STATE SYNCHRONIZATION
// ============================================================================
static esp_err_t execute_ota(const char *url)
{
    cloud_print("Downloading payload...");
    esp_http_client_config_t http_config = {
        .url = url,
        .skip_cert_common_name_check = true,
        .keep_alive_enable = true,
        .max_redirection_count = 5,
        .buffer_size = 4096,
        .timeout_ms = 30000,
    };
    esp_https_ota_config_t ota_config = { .http_config = &http_config };

    esp_err_t ret = esp_https_ota(&ota_config);
    if (ret == ESP_OK) {
        cloud_print("OTA Flash Complete. Rebooting...");
        vTaskDelay(pdMS_TO_TICKS(1500));
        esp_restart();
    } else {
        cloud_print("OTA Flash Failed!");
    }
    return ret;
}

static void ota_polling_task(void *pvParameters)
{
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    start_runtime_webserver();

    char boot_msg[192];
    snprintf(boot_msg, sizeof(boot_msg),
             ">>> [BLINK TEST VERIFIED] FLEET NODE [%s] ONLINE | Wi-Fi: %s | IP: %s <<<", s_device_id, s_active_ssid, s_device_ip);
    cloud_print(boot_msg);

    // Initial sync of current states to Firebase
    sync_relays_to_cloud();

    char rx_buffer[1024];
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(15000));

        esp_http_client_config_t config = {
            .url = s_db_url,
            .method = HTTP_METHOD_GET,
            .skip_cert_common_name_check = true,
            .timeout_ms = 15000,
        };

        esp_http_client_handle_t client = esp_http_client_init(&config);
        if (!client) continue;

        esp_err_t err = esp_http_client_open(client, 0);
        if (err == ESP_OK) {
            esp_http_client_fetch_headers(client);
            int bytes_read = esp_http_client_read_response(client, rx_buffer, sizeof(rx_buffer) - 1);
            if (bytes_read > 0) {
                rx_buffer[bytes_read] = '\0';
                cJSON *root = cJSON_Parse(rx_buffer);
                if (root) {
                    // Check Cloud FOTA Release
                    cJSON *ver_node = cJSON_GetObjectItem(root, "version");
                    cJSON *url_node = cJSON_GetObjectItem(root, "firmwareUrl");
                    if (ver_node && url_node && cJSON_IsNumber(ver_node) && cJSON_IsString(url_node)) {
                        int64_t cloud_version = (int64_t)ver_node->valuedouble;
                        char target_url[512];
                        strncpy(target_url, url_node->valuestring, sizeof(target_url) - 1);
                        target_url[sizeof(target_url) - 1] = '\0';

                        if (s_current_version == 0) {
                            s_current_version = cloud_version;
                        } else if (cloud_version > s_current_version) {
                            s_current_version = cloud_version;
                            cJSON_Delete(root);
                            esp_http_client_close(client);
                            esp_http_client_cleanup(client);
                            execute_ota(target_url);
                            continue;
                        }
                    }

                    // Check Inbound Cloud Relay Command
                    cJSON *relays_node = cJSON_GetObjectItem(root, "relays");
                    if (relays_node) {
                        cJSON *r1 = cJSON_GetObjectItem(relays_node, "r1");
                        cJSON *r2 = cJSON_GetObjectItem(relays_node, "r2");
                        cJSON *r3 = cJSON_GetObjectItem(relays_node, "r3");
                        cJSON *r4 = cJSON_GetObjectItem(relays_node, "r4");

                        bool changed = false;
                        if (r1 && cJSON_IsNumber(r1) && s_relay_states[0] != r1->valueint) { s_relay_states[0] = r1->valueint; changed = true; }
                        if (r2 && cJSON_IsNumber(r2) && s_relay_states[1] != r2->valueint) { s_relay_states[1] = r2->valueint; changed = true; }
                        if (r3 && cJSON_IsNumber(r3) && s_relay_states[2] != r3->valueint) { s_relay_states[2] = r3->valueint; changed = true; }
                        if (r4 && cJSON_IsNumber(r4) && s_relay_states[3] != r4->valueint) { s_relay_states[3] = r4->valueint; changed = true; }

                        if (changed) {
                            for (int i = 0; i < 4; i++) {
                                gpio_set_level(s_relay_pins[i], s_relay_states[i] ? RELAY_ON : RELAY_OFF);
                            }
                            save_relay_states_to_nvs();
                            ESP_LOGI(TAG, "Hardware updated from inbound Cloud sync.");
                        }
                    }
                    cJSON_Delete(root);
                }
            }
            esp_http_client_close(client);
        }
        esp_http_client_cleanup(client);
    }
}

// ============================================================================
// 8. RAPID BLINK TEST TASK (GPIO 2 - BLUE ONBOARD LED)
// ============================================================================
static void blink_test_task(void *pvParameters)
{
    gpio_reset_pin(BLINK_GPIO);
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);

    while (1) {
        gpio_set_level(BLINK_GPIO, 1);
        vTaskDelay(pdMS_TO_TICKS(150)); // 150ms ON
        gpio_set_level(BLINK_GPIO, 0);
        vTaskDelay(pdMS_TO_TICKS(150)); // 150ms OFF
    }
}

// ============================================================================
// 9. WI-FI EVENT STACK
// ============================================================================
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && (event_id == WIFI_EVENT_STA_START || event_id == WIFI_EVENT_STA_DISCONNECTED)) {
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        snprintf(s_device_ip, sizeof(s_device_ip), IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void app_main(void)
{
    esp_ota_mark_app_valid_cancel_rollback();

    // 1. Initialize NVS Flash
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // 2. Discover Hardware Identity and Configure Endpoints
    init_device_identity();

    // 3. Configure Relay Pins
    for (int i = 0; i < 4; i++) {
        gpio_reset_pin(s_relay_pins[i]);
        gpio_set_direction(s_relay_pins[i], GPIO_MODE_OUTPUT);
    }

    // 4. Restore Relay States from NVS immediately (Power Cut Memory)
    load_relay_states_from_nvs();

    // 5. Start Rapid Blink Task (Confirms Firmware is Running)
    xTaskCreate(&blink_test_task, "blink_test_task", 2048, NULL, 5, NULL);

    // 6. Initialize Network Stack
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    xTaskCreate(&factory_reset_button_task, "reset_btn_task", 2048, NULL, 10, NULL);

    s_is_provisioned = load_stored_wifi(s_active_ssid, sizeof(s_active_ssid),
                                        s_active_pass, sizeof(s_active_pass));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    if (!s_is_provisioned) {
        ESP_LOGW(TAG, "Device [%s] unprovisioned. Broadcasting hotspot: %s", s_device_id, s_ap_ssid);
        esp_netif_create_default_wifi_ap();
        esp_netif_create_default_wifi_sta();

        wifi_config_t ap_config = {
            .ap = {
                .channel = 1,
                .password = "",
                .max_connection = 4,
                .authmode = WIFI_AUTH_OPEN
            },
        };
        strncpy((char *)ap_config.ap.ssid, s_ap_ssid, sizeof(ap_config.ap.ssid));
        ap_config.ap.ssid_len = strlen(s_ap_ssid);

        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
        ESP_ERROR_CHECK(esp_wifi_start());

        xTaskCreate(&dns_server_task, "dns_server_task", 4096, NULL, 5, NULL);
        start_provisioning_server();

    } else {
        ESP_LOGI(TAG, "Device [%s] joining: %s", s_device_id, s_active_ssid);
        s_wifi_event_group = xEventGroupCreate();
        esp_netif_create_default_wifi_sta();

        esp_event_handler_instance_t instance_any_id, instance_got_ip;
        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));

        wifi_config_t sta_config = {0};
        strncpy((char*)sta_config.sta.ssid, s_active_ssid, sizeof(sta_config.sta.ssid));
        strncpy((char*)sta_config.sta.password, s_active_pass, sizeof(sta_config.sta.password));
        sta_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
        ESP_ERROR_CHECK(esp_wifi_start());

        xTaskCreate(&ota_polling_task, "ota_polling_task", 8192, NULL, 5, NULL);
    }
}