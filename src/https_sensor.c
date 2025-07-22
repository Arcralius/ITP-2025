#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// Configuration
#define HEARTBEAT_TIMER 15
#define SECRET_TIMER 10
#define MAX_DNS_BATCH_SIZE 5
#define DNS_SEND_INTERVAL 10
#define MAX_UDP_BATCH_SIZE 5
#define UDP_SEND_INTERVAL 10
#define MAX_JSON_SIZE 4096

// Global variables
char SENSOR_ID[64] = "";
char SHARED_SECRET[64] = "";

char SERVER_URL_BASE[256] = "http://localhost:4000";
char SERVER_URL_HEARTBEAT[256];
char SERVER_URL_CAPTURED_UDP[256];
char SERVER_URL_DNS_DATA[256];
char SERVER_URL_SECRET[256];

typedef struct {
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    char *payload;
    size_t payload_len;
} udp_packet_info;

typedef struct {
    char domain[256];
    char resolved_ip[16];
    char status[16];
} dns_query;

udp_packet_info *collected_udp_packet_info = NULL;
size_t udp_packet_count = 0;
time_t last_udp_send_time = 0;

dns_query *collected_dns_queries = NULL;
size_t dns_query_count = 0;
time_t last_dns_send_time = 0;

pthread_mutex_t udp_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t dns_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t secret_mutex = PTHREAD_MUTEX_INITIALIZER;

// Utility functions
void generate_signature(const char *sensor_id, const char *timestamp, const char *secret, char *signature) {
    char message[256];
    snprintf(message, sizeof(message), "%s|%s", sensor_id, timestamp);
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, secret, strlen(secret), EVP_sha256(), NULL);
    HMAC_Update(ctx, (unsigned char*)message, strlen(message));
    unsigned int len;
    HMAC_Final(ctx, digest, &len);
    HMAC_CTX_free(ctx);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&signature[i*2], "%02x", (unsigned int)digest[i]);
    }
}

void get_current_timestamp(char *timestamp, size_t size) {
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(timestamp, size, "%Y-%m-%dT%H:%M:%SZ", tm);
}

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    // Add padding
    for (size_t i = 0; i < (3 - input_length % 3) % 3; i++) {
        encoded_data[*output_length - 1 - i] = '=';
    }

    encoded_data[*output_length] = '\0';
    return encoded_data;
}

// Simple JSON generation functions
void json_add_string(char *json, size_t *pos, const char *key, const char *value) {
    if (*pos > 0) {
        json[(*pos)++] = ',';
    }
    *pos += sprintf(json + *pos, "\"%s\":\"%s\"", key, value);
}

void json_start_object(char *json, size_t *pos) {
    json[(*pos)++] = '{';
}

void json_end_object(char *json, size_t *pos) {
    json[(*pos)++] = '}';
}

void json_start_array(char *json, size_t *pos, const char *key) {
    if (*pos > 0) {
        json[(*pos)++] = ',';
    }
    *pos += sprintf(json + *pos, "\"%s\":[", key);
}

void json_end_array(char *json, size_t *pos) {
    json[(*pos)++] = ']';
}

// HTTP functions
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    printf("%.*s", (int)realsize, (char*)contents);
    return realsize;
}

void send_http_request(const char *url, const char *payload) {
    CURL *curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
}

void send_heartbeat() {
    char timestamp[64];
    get_current_timestamp(timestamp, sizeof(timestamp));
    
    char signature[65];
    generate_signature(SENSOR_ID, timestamp, SHARED_SECRET, signature);
    
    char json[MAX_JSON_SIZE] = {0};
    size_t pos = 0;
    
    json_start_object(json, &pos);
    json_add_string(json, &pos, "sensor_id", SENSOR_ID);
    json_add_string(json, &pos, "timestamp", timestamp);
    json_add_string(json, &pos, "signature", signature);
    json_end_object(json, &pos);
    
    size_t b64_len;
    char *encoded_payload = base64_encode((unsigned char *)json, pos, &b64_len);
    
    printf("[Heartbeat] Sent at %s\n", timestamp);
    send_http_request(SERVER_URL_HEARTBEAT, encoded_payload);
    
    free(encoded_payload);
}

void send_dns_data() {
    if (dns_query_count == 0) return;
    
    char timestamp[64];
    get_current_timestamp(timestamp, sizeof(timestamp));
    
    char signature[65];
    generate_signature(SENSOR_ID, timestamp, SHARED_SECRET, signature);
    
    char json[MAX_JSON_SIZE] = {0};
    size_t pos = 0;
    
    json_start_object(json, &pos);
    json_add_string(json, &pos, "sensor_id", SENSOR_ID);
    json_add_string(json, &pos, "timestamp", timestamp);
    json_add_string(json, &pos, "signature", signature);
    
    json_start_array(json, &pos, "dns_queries");
    for (size_t i = 0; i < dns_query_count; i++) {
        if (i > 0) json[pos++] = ',';
        
        size_t temp_pos = 0;
        char temp_json[512] = {0};
        json_start_object(temp_json, &temp_pos);
        json_add_string(temp_json, &temp_pos, "domain", collected_dns_queries[i].domain);
        json_add_string(temp_json, &temp_pos, "resolved_ip", collected_dns_queries[i].resolved_ip);
        json_add_string(temp_json, &temp_pos, "status", collected_dns_queries[i].status);
        json_end_object(temp_json, &temp_pos);
        
        strcpy(json + pos, temp_json);
        pos += temp_pos;
    }
    json_end_array(json, &pos);
    json_end_object(json, &pos);
    
    size_t b64_len;
    char *encoded_payload = base64_encode((unsigned char *)json, pos, &b64_len);
    
    printf("[DNS Data] Sent %zu queries at %s\n", dns_query_count, timestamp);
    send_http_request(SERVER_URL_DNS_DATA, encoded_payload);
    
    free(encoded_payload);
    
    pthread_mutex_lock(&dns_mutex);
    free(collected_dns_queries);
    collected_dns_queries = NULL;
    dns_query_count = 0;
    pthread_mutex_unlock(&dns_mutex);
}

void send_captured_udp_data() {
    if (udp_packet_count == 0) return;
    
    char timestamp[64];
    get_current_timestamp(timestamp, sizeof(timestamp));
    
    char signature[65];
    generate_signature(SENSOR_ID, timestamp, SHARED_SECRET, signature);
    
    char json[MAX_JSON_SIZE] = {0};
    size_t pos = 0;
    
    json_start_object(json, &pos);
    json_add_string(json, &pos, "sensor_id", SENSOR_ID);
    json_add_string(json, &pos, "timestamp", timestamp);
    json_add_string(json, &pos, "signature", signature);
    
    json_start_array(json, &pos, "packet_info");
    for (size_t i = 0; i < udp_packet_count; i++) {
        if (i > 0) json[pos++] = ',';
        
        size_t temp_pos = 0;
        char temp_json[1024] = {0};
        json_start_object(temp_json, &temp_pos);
        json_add_string(temp_json, &temp_pos, "src_ip", collected_udp_packet_info[i].src_ip);
        json_add_string(temp_json, &temp_pos, "dst_ip", collected_udp_packet_info[i].dst_ip);
        temp_pos += sprintf(temp_json + temp_pos, "\"src_port\":%d,", collected_udp_packet_info[i].src_port);
        temp_pos += sprintf(temp_json + temp_pos, "\"dst_port\":%d,", collected_udp_packet_info[i].dst_port);
        
        size_t b64_len;
        char *encoded_payload = base64_encode((unsigned char *)collected_udp_packet_info[i].payload, 
                                            collected_udp_packet_info[i].payload_len, &b64_len);
        temp_pos += sprintf(temp_json + temp_pos, "\"payload\":\"%s\"", encoded_payload);
        free(encoded_payload);
        
        json_end_object(temp_json, &temp_pos);
        
        strcpy(json + pos, temp_json);
        pos += temp_pos;
    }
    json_end_array(json, &pos);
    json_end_object(json, &pos);
    
    size_t b64_len;
    char *encoded_payload = base64_encode((unsigned char *)json, pos, &b64_len);
    
    printf("[Captured UDP] Sent %zu packet details at %s\n", udp_packet_count, timestamp);
    send_http_request(SERVER_URL_CAPTURED_UDP, encoded_payload);
    
    free(encoded_payload);
    
    pthread_mutex_lock(&udp_mutex);
    for (size_t i = 0; i < udp_packet_count; i++) {
        free(collected_udp_packet_info[i].payload);
    }
    free(collected_udp_packet_info);
    collected_udp_packet_info = NULL;
    udp_packet_count = 0;
    pthread_mutex_unlock(&udp_mutex);
}

void fetch_shared_secret() {
    printf("[Secret Sync] Attempting to fetch updated secret...\n");
    
    char timestamp[64];
    get_current_timestamp(timestamp, sizeof(timestamp));
    
    char signature[65];
    generate_signature(SENSOR_ID, timestamp, SHARED_SECRET, signature);
    
    CURL *curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        char sensor_header[128];
        snprintf(sensor_header, sizeof(sensor_header), "X-Sensor-ID: %s", SENSOR_ID);
        headers = curl_slist_append(headers, sensor_header);
        
        char timestamp_header[128];
        snprintf(timestamp_header, sizeof(timestamp_header), "X-Timestamp: %s", timestamp);
        headers = curl_slist_append(headers, timestamp_header);
        
        char signature_header[128];
        snprintf(signature_header, sizeof(signature_header), "X-Signature: %s", signature);
        headers = curl_slist_append(headers, signature_header);
        
        curl_easy_setopt(curl, CURLOPT_URL, SERVER_URL_SECRET);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if (response_code == 200) {
                printf("[Secret Sync] Successfully updated shared secret at %s\n", timestamp);
            } else {
                printf("[Secret Sync Error] Failed to fetch secret. Status: %ld\n", response_code);
            }
        } else {
            fprintf(stderr, "[Secret Sync Error] Could not connect to server: %s\n", curl_easy_strerror(res));
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
}

// Packet processing
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14); // Skip Ethernet header
    if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        
        pthread_mutex_lock(&udp_mutex);
        
        // Resize array if needed
        if (udp_packet_count % MAX_UDP_BATCH_SIZE == 0) {
            udp_packet_info *new_ptr = realloc(collected_udp_packet_info, 
                                              (udp_packet_count + MAX_UDP_BATCH_SIZE) * sizeof(udp_packet_info));
            if (new_ptr == NULL) {
                fprintf(stderr, "Memory allocation failed\n");
                pthread_mutex_unlock(&udp_mutex);
                return;
            }
            collected_udp_packet_info = new_ptr;
        }
        
        // Store packet info
        udp_packet_info *info = &collected_udp_packet_info[udp_packet_count];
        strncpy(info->src_ip, inet_ntoa(ip_header->ip_src), sizeof(info->src_ip));
        strncpy(info->dst_ip, inet_ntoa(ip_header->ip_dst), sizeof(info->dst_ip));
        info->src_port = ntohs(udp_header->uh_sport);
        info->dst_port = ntohs(udp_header->uh_dport);
        
        // Store payload
        size_t payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
        info->payload = malloc(payload_len);
        if (info->payload == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            pthread_mutex_unlock(&udp_mutex);
            return;
        }
        memcpy(info->payload, packet + 14 + (ip_header->ip_hl * 4) + sizeof(struct udphdr), payload_len);
        info->payload_len = payload_len;
        
        udp_packet_count++;
        
        if (udp_packet_count >= MAX_UDP_BATCH_SIZE) {
            send_captured_udp_data();
            last_udp_send_time = time(NULL);
        }
        
        pthread_mutex_unlock(&udp_mutex);
    }
}

// Thread functions
void *heartbeat_loop(void *arg) {
    while (1) {
        send_heartbeat();
        sleep(HEARTBEAT_TIMER);
    }
    return NULL;
}

void *packet_sniffer_loop(void *arg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return NULL;
    }
    
    // Filter for UDP packets only
    struct bpf_program fp;
    char filter_exp[] = "udp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    
    printf("Starting packet sniffer...\n");
    pcap_loop(handle, 0, process_packet, NULL);
    pcap_close(handle);
    return NULL;
}

void *secret_sync_loop(void *arg) {
    while (1) {
        sleep(SECRET_TIMER);
        fetch_shared_secret();
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <sensor_id> <shared_secret>\n", argv[0]);
        return 1;
    }
    
    // Initialize configuration
    strncpy(SENSOR_ID, argv[1], sizeof(SENSOR_ID));
    strncpy(SHARED_SECRET, argv[2], sizeof(SHARED_SECRET));
    
    // Initialize server URLs
    snprintf(SERVER_URL_HEARTBEAT, sizeof(SERVER_URL_HEARTBEAT), "%s/heartbeat", SERVER_URL_BASE);
    snprintf(SERVER_URL_CAPTURED_UDP, sizeof(SERVER_URL_CAPTURED_UDP), "%s/captured_udp_packets", SERVER_URL_BASE);
    snprintf(SERVER_URL_DNS_DATA, sizeof(SERVER_URL_DNS_DATA), "%s/dns_data", SERVER_URL_BASE);
    snprintf(SERVER_URL_SECRET, sizeof(SERVER_URL_SECRET), "%s/secret", SERVER_URL_BASE);
    
    printf("--- Sensor Initializing ---\n");
    printf("Sensor ID: %s\n", SENSOR_ID);
    printf("-----------------------------\n");
    
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_ALL);
    
    // Create threads
    pthread_t heartbeat_thread, sniffer_thread, secret_thread;
    
    if (pthread_create(&heartbeat_thread, NULL, heartbeat_loop, NULL) != 0) {
        fprintf(stderr, "Error creating heartbeat thread\n");
        return 1;
    }
    
    if (pthread_create(&sniffer_thread, NULL, packet_sniffer_loop, NULL) != 0) {
        fprintf(stderr, "Error creating sniffer thread\n");
        return 1;
    }
    
    if (pthread_create(&secret_thread, NULL, secret_sync_loop, NULL) != 0) {
        fprintf(stderr, "Error creating secret sync thread\n");
        return 1;
    }
    
    printf("\n--- Sensor is Running ---\n");
    printf("  -> Sending heartbeats and captured data via HTTP.\n");
    printf("  -> Syncing shared secret with server every 10 seconds.\n");
    printf("------------------------------------------\n\n");
    
    // Main loop
    while (1) {
        time_t current_time = time(NULL);
        
        pthread_mutex_lock(&dns_mutex);
        if (dns_query_count > 0 && (current_time - last_dns_send_time) >= DNS_SEND_INTERVAL) {
            printf("Sending DNS batch due to timeout (%zu queries)...\n", dns_query_count);
            send_dns_data();
            last_dns_send_time = current_time;
        }
        pthread_mutex_unlock(&dns_mutex);
        
        pthread_mutex_lock(&udp_mutex);
        if (udp_packet_count > 0 && (current_time - last_udp_send_time) >= UDP_SEND_INTERVAL) {
            printf("Sending captured UDP batch due to timeout (%zu packets)...\n", udp_packet_count);
            send_captured_udp_data();
            last_udp_send_time = current_time;
        }
        pthread_mutex_unlock(&udp_mutex);
        
        sleep(1);
    }
    
    // Cleanup (unreachable in this example)
    curl_global_cleanup();
    return 0;
}