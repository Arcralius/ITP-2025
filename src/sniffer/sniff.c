#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <curl/curl.h>
#include <time.h>

#define DNS_PORT 53
#define LOG_FILE "dns_traffic.txt"
#define SERVER_URL "http://localhost:5000/collect"

long last_sent_position = 0;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

struct dns_header {
    unsigned short id;
    unsigned char flags[2];
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

void parse_dns_query(const u_char *dns_start, char *domain, size_t max_len, int *qtype) {
    int len = dns_start[0];
    int i = 1;
    int pos = 0;
    while (len && i < 256 && pos < max_len - 1) {
        for (int j = 0; j < len && i < 256 && pos < max_len - 1; j++) {
            domain[pos++] = dns_start[i++];
        }
        domain[pos++] = '.';
        len = dns_start[i++];
    }
    if (pos > 0) domain[pos - 1] = '\0';
    else domain[0] = '\0';

    *qtype = (dns_start[i] << 8) | dns_start[i + 1];
}

const char* get_qtype_name(int qtype) {
    switch (qtype) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        default: return "Other";
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct ip *ip_hdr = (struct ip *)(bytes + 14);
    if (ip_hdr->ip_p != IPPROTO_UDP) return;

    struct udphdr *udp_hdr = (struct udphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));
    if (ntohs(udp_hdr->uh_dport) != DNS_PORT) return;

    struct dns_header *dns = (struct dns_header *)((u_char *)udp_hdr + sizeof(struct udphdr));
    if ((dns->flags[0] & 0x80) != 0) return; // Skip responses

    char domain[256];
    int qtype = 0;
    parse_dns_query((u_char *)dns + sizeof(struct dns_header), domain, sizeof(domain), &qtype);

    if (!(qtype == 1 || qtype == 2 || qtype == 5 || qtype == 6 || qtype == 12 || qtype == 15 || qtype == 16 || qtype == 28))
        return;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, sizeof(dst_ip));

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%F %T", localtime(&now));

    pthread_mutex_lock(&file_mutex);
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "%s | Src: %s | Dst: %s | Domain: %s | Type: %s\n",
                timestamp, src_ip, dst_ip, domain, get_qtype_name(qtype));
        fclose(log);
    }
    pthread_mutex_unlock(&file_mutex);

    printf("Logged: %s -> %s | %s | %s\n", src_ip, dst_ip, domain, get_qtype_name(qtype));
}

void *send_logs(void *arg) {
    while (1) {
        pthread_mutex_lock(&file_mutex);
        FILE *file = fopen(LOG_FILE, "r");
        if (file) {
            fseek(file, 0, SEEK_END);
            long size = ftell(file);
            if (size > last_sent_position) {
                fseek(file, last_sent_position, SEEK_SET);
                char *buffer = malloc(size - last_sent_position + 1);
                fread(buffer, 1, size - last_sent_position, file);
                buffer[size - last_sent_position] = '\0';

                CURL *curl = curl_easy_init();
                if (curl) {
                    char *encoded_data = curl_easy_escape(curl, buffer, 0);
                    if (encoded_data) {
                        size_t post_size = strlen("content=") + strlen(encoded_data) + 1;
                        char *post_fields = malloc(post_size);
                        if (post_fields) {
                            snprintf(post_fields, post_size, "content=%s", encoded_data);

                            curl_easy_setopt(curl, CURLOPT_URL, SERVER_URL);
                            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
                            struct curl_slist *headers = NULL;
                            headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
                            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

                            CURLcode res = curl_easy_perform(curl);
                            if (res == CURLE_OK) {
                                printf("[Sent] %ld bytes\n", size - last_sent_position);
                                last_sent_position = ftell(file);
                            } else {
                                fprintf(stderr, "[Error] curl: %s\n", curl_easy_strerror(res));
                            }

                            free(post_fields);
                            curl_slist_free_all(headers);
                        } else {
                            fprintf(stderr, "[Error] malloc failed for post_fields\n");
                        }
                        curl_free(encoded_data);
                    } else {
                        fprintf(stderr, "[Error] curl_easy_escape failed\n");
                    }
                    curl_easy_cleanup(curl);
                }
                free(buffer);
            }
            fclose(file);
        }
        pthread_mutex_unlock(&file_mutex);
        sleep(60);
    }
    return NULL;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = pcap_lookupdev(errbuf);
    if (!dev) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    printf("Sniffing on device: %s\n", dev);
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    pthread_t sender_thread;
    pthread_create(&sender_thread, NULL, send_logs, NULL);

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
