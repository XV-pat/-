#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For uint16_t, uint32_t
#include <time.h>   // For select, time

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h> // For InetPton, inet_ntop
#include <windows.h>  // For Sleep()
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_ntop, inet_pton
#include <unistd.h> // For close and usleep()
#include <sys/select.h>
#include <strings.h> // ���� strcasecmp (��ĳЩϵͳ�ϣ�����Linux)
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

#define DNS_PORT 53
#define BUFFER_SIZE 512       // UDP DNS ���ݰ�����С
#define MAX_DOMAIN_ENTRIES 2048
#define MAX_ID_MAPPINGS 256
#define UPSTREAM_TIMEOUT_SEC 2 // ���� DNS ��������ʱʱ��Ϊ2��

// --- ȫ�ֱ��������� ---
int DEBUG_LEVEL = 0; // 0: ��, 1: ����, 2: ��ϸ
char UPSTREAM_DNS_SERVER_IP[16] = "202.106.0.20"; // Ĭ������ DNS
char CONFIG_FILENAME[256] = "dnsrelay.txt";     // Ĭ�������ļ�

// --- DNS �ṹ�� (RFC1035 4.1) ---

// ͷ���ڸ�ʽ (RFC1035 4.1.1)
#pragma pack(push, 1) // ��ȷ���
typedef struct {
    uint16_t id;       // ��ʶ��

    uint8_t rd : 1;     //�����ݹ�
    uint8_t tc : 1;     // ��Ϣ���ض�
    uint8_t aa : 1;     // Ȩ����
    uint8_t opcode : 4; // ������
    uint8_t qr : 1;     // ��ѯ/��Ӧ��־ (0 ��ʾ��ѯ, 1 ��ʾ��Ӧ)

    uint8_t rcode : 4;  // ��Ӧ��
    uint8_t z : 3;      // �����ֶ�
    uint8_t ra : 1;     // �ݹ����

    uint16_t qdcount;  // ������
    uint16_t ancount;  // �ش���Դ��¼��
    uint16_t nscount;  // Ȩ�����Ʒ�������
    uint16_t arcount;  // ������Դ��¼��
} DnsHeader;

// ����ڸ�ʽ (RFC1035 4.1.2)
typedef struct {
    // QNAME �ǿɱ䳤�ȵ�, ��������
    uint16_t qtype;  // ��ѯ����
    uint16_t qclass; // ��ѯ��
} DnsQuestionTrailer;

// ��Դ��¼��ʽ (RFC1035 4.1.3 / 3.2.1)
typedef struct {
    // NAME (�ɱ䳤��, ��00��ָ�����)
    // TYPE
    // CLASS
    // TTL
    // RDLENGTH
    // RDATA (�ɱ䳤��)
    uint16_t type;     // RR TYPE code
    uint16_t class_rr; // RR CLASS code
    uint32_t ttl;      // time interval that the resource record may be cached
    uint16_t rdlength; // length in octets of the RDATA field
    // RDATA follows
} DnsResourceRecordPreamble;
#pragma pack(pop)

// --- ��������ӳ�� ---
typedef struct {
    char domain_name[256];
    struct in_addr ip_address;
    int is_blocking;
} DomainEntry;
DomainEntry domain_mappings[MAX_DOMAIN_ENTRIES];
int domain_map_count = 0;

// --- �����м̵�IDת�� ---
typedef struct {
    uint16_t original_id;
    uint16_t relayed_id;
    struct sockaddr_in client_addr;
    time_t timestamp;
    int active;
} IdMapping;
IdMapping id_translation_table[MAX_ID_MAPPINGS];
uint16_t next_relayed_id = 1000; // RFC1035 4.1.1 ID��һ��16λ��ʶ��

// --- �������� ---

// �� DNS ���Ƹ�ʽת��Ϊ�ַ��������ش� dns_name_ptr ��ȡ�� QNAME ���ֽ�����
// �˺������ڸ�׼ȷ�ؼ���ԭʼ��Ϣ��QNAME��ռ�õ��ֽ���������ָ�롣
int dns_name_to_string(const unsigned char* qname_in_message, char* out_str, const unsigned char* buffer_start, int buffer_len) {
    const unsigned char* p = qname_in_message; // ָ����Ϣ��QNAME��ʼλ�õ�ָ��
    char* out_p = out_str;        // ָ������ַ�����������ָ��
    int len_in_message = 0;       // QNAME����Ϣ��ʵ��ռ�õĳ���
    int name_parsed_once = 0;     // ������������Ƿ����ٱ����ֽ��������ڴ��������"."��
    int hops = 0;                 // ��ָֹ��ѭ��

    if (!qname_in_message || !out_str || !buffer_start || buffer_len <= 0) return -1;
    if (qname_in_message < buffer_start || qname_in_message >= buffer_start + buffer_len) return -1;

    *out_p = '\0'; // ��ʼ������ַ���Ϊ��

    while (*p != 0 && hops < 10) { // ���10��ָ����ת
        if (p < buffer_start || p >= buffer_start + buffer_len) { // Խ����
            if (DEBUG_LEVEL > 0) fprintf(stderr, "����: dns_name_to_string ��ָ��Խ�� (p)��\n"); return -1;
        }
        name_parsed_once = 1;
        if ((*p & 0xC0) == 0xC0) { // ��ָ�� RFC1035 4.1.4 [cite: 518, 1400]
            if (p + 1 >= buffer_start + buffer_len) { // ָ�뱾����Ҫ2�ֽ�
                if (DEBUG_LEVEL > 0) fprintf(stderr, "����: dns_name_to_string ��ָ�벻������\n"); return -1;
            }
            uint16_t offset = ntohs(*(uint16_t*)p) & 0x3FFF;
            if (len_in_message == 0) { // �������QNAME�Ŀ�ʼ����QNAME����Ϣ��ռ��2�ֽ�
                len_in_message = 2;
            } // ������ǿ�ʼ������ǩ���ָ�룩����ָ��ĳ����Ѱ�����֮ǰ��ǩ��len_in_message������ (��Ϊ�����ָ��)
              // ����˵�����һ����ǩ���к����һ��ָ�룬��ô���ָ���2�ֽڻ�����Ǹ���ǩ����ĩβ��0�ֽڡ�
              // �˴��򻯣����QNAME��ָ�뿪ʼ���򳤶�Ϊ2�����QNAME�Ǳ�ǩ����+ָ�룬��len_in_message����ѭ������ʱ�Ǳ�ǩ����+ָ��ĳ��ȡ�

            if (buffer_start + offset >= buffer_start + buffer_len) {
                if (DEBUG_LEVEL > 0) fprintf(stderr, "����: dns_name_to_string ��ָ��ƫ�� (0x%X) Խ�硣\n", offset); return -1;
            }
            p = buffer_start + offset; // ��ת
            hops++;
            // ����ת���������ַ������������Ҳ�����'.'��β�������'.'
            if (out_p != out_str && *(out_p - 1) != '.' && *p != 0) {
                *out_p++ = '.';
            }
            continue; // ����λ�ü�������
        }
        else { // �Ǳ�ǩ
            uint8_t label_len = *p;
            if (label_len > 63) {
                if (DEBUG_LEVEL > 0) fprintf(stderr, "����: DNS��ǩ���� (0x%X) �Ƿ� (>63)��\n", label_len); return -1;
            }
            // ����ǩ����+�����Ƿ�Խ��
            if (p + 1 + label_len >= buffer_start + buffer_len + 1) { // p+1+label_len����һ����ǩ�Ŀ�ʼ���β��0
                if (DEBUG_LEVEL > 0) fprintf(stderr, "����: DNS��ǩ���� (���� %u @ %td) ������������ (�ܳ� %d)��\n", label_len, p - buffer_start, buffer_len); return -1;
            }

            if (len_in_message == 0 || (qname_in_message + len_in_message != p)) {
                // ���len_in_messageΪ0���״Σ������ߵ�ǰp��λ�ò��ǽ������ϴμ�¼��len_in_message֮��˵��������ָ����ת��
                // ��ô����ֻ���㵱ǰ���ڽ����ġ���ָ�벿�ֵĳ���
                // ��һ���ֵļ����ǣ�len_in_messageֻ��¼��qname_in_message��ʼ�������ֽ���
            }


            p++; // ���������ֽ�
            // �����������ĵ�һ����ǩ�Σ�����֮ǰû��д��㣬����ӵ�
            if (out_p != out_str && *(out_p - 1) != '.') {
                *out_p++ = '.';
            }
            memcpy(out_p, p, label_len);
            p += label_len;
            out_p += label_len;
        }
    }
    *out_p = '\0'; // �ַ�������

    // ����QNAME����Ϣ�е�ʵ�ʳ���
    // �������qname_in_message����һ��0 (������)
    if (*qname_in_message == 0 && !name_parsed_once) {
        return 1;
    }
    // ���򣬳����Ǵ� qname_in_message ����ǰ p ָ�루��ָ���β��0��ָ�룩�ľ���
    // ������м���ָ�룬ʵ�ʳ������״�����ָ��ʱ��λ�� + 2
    // ���������Ŀ������� qname_in_message ��ԭ���ݰ���ռ�˶����ֽ�
    // ��򵥵ķ����ǣ���qname_in_message��ʼɨ�裬ֱ������0����һ��ָ���ĩβ
    const unsigned char* scanner = qname_in_message;
    while (scanner < buffer_start + buffer_len) {
        if ((*scanner & 0xC0) == 0xC0) { // ��ָ��
            len_in_message = (scanner - qname_in_message) + 2;
            goto end_len_calc;
        }
        else if (*scanner == 0) { // �ǽ�β0
            len_in_message = (scanner - qname_in_message) + 1;
            goto end_len_calc;
        }
        else { // �Ǳ�ǩ����
            uint8_t l = *scanner;
            if (l > 63 || scanner + 1 + l >= buffer_start + buffer_len + 1) { return -1; /* ��ʽ���� */ }
            scanner += (1 + l);
        }
    }
    return -1; // ���ѭ��������û�ҵ���β��˵����ʽ����򳬳�buffer_len

end_len_calc:
    if (hops >= 10 && DEBUG_LEVEL > 0) fprintf(stderr, "���棺��������ʱָ����ת���࣬���ܴ���ѭ����\n");
    return len_in_message;
}


// ���ַ���ת��ΪDNS���Ƹ�ʽ������DNS��ʽ���Ƶĳ��ȡ�
int string_to_dns_name(const char* str_name, unsigned char* out_dns_name) { /* ... (����һ�汾��ͬ) ... */
    char name_copy[256]; strncpy(name_copy, str_name, 255); name_copy[255] = '\0';
    unsigned char* dns_ptr = out_dns_name; char* token = strtok(name_copy, "."); int total_len = 0;
    while (token != NULL) {
        uint8_t len = strlen(token); if (len > 63) { if (DEBUG_LEVEL > 0) fprintf(stderr, "����: ������ǩ '%s' ���� (>63�ֽ�)��\n", token); return -1; }
        *dns_ptr++ = len; memcpy(dns_ptr, token, len); dns_ptr += len; total_len += (len + 1); token = strtok(NULL, ".");
    }
    *dns_ptr = 0; total_len += 1;
    if (total_len > 255) { if (DEBUG_LEVEL > 0) fprintf(stderr, "����: ת�����DNS�����ܳ��� %d ���� (>255�ֽ�)��\n", total_len); return -1; }
    return total_len;
}

// �������ļ���������ӳ��
void load_domain_mappings() { /* ... (����һ�汾��ͬ) ... */
    FILE* file = fopen(CONFIG_FILENAME, "r");
    if (!file) {
        if (DEBUG_LEVEL > 0) fprintf(stderr, "����: �������ļ� '%s' ʧ�ܡ�", CONFIG_FILENAME);
#ifdef _WIN32
        if (DEBUG_LEVEL > 0) { char errBuf[256]; DWORD dwError = GetLastError(); FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errBuf, sizeof(errBuf), NULL); fprintf(stderr, " ϵͳ������� %lu: %s\n", dwError, errBuf); }
#else
        if (DEBUG_LEVEL > 0) perror(" ϵͳ����");
#endif
        if (DEBUG_LEVEL > 0) fprintf(stderr, "����ʹ�ñ�������������\n"); return;
    }
    char line[512]; int line_num = 0; domain_map_count = 0;
    while (fgets(line, sizeof(line), file) && domain_map_count < MAX_DOMAIN_ENTRIES) {
        line_num++; char ip_str[100]; char domain_str_from_file[256];
        line[strcspn(line, "\r\n")] = 0; if (line[0] == '\0' || line[0] == '#' || line[0] == ';') continue;
        if (sscanf(line, "%99s %255s", ip_str, domain_str_from_file) == 2) {
            if (strcmp(ip_str, "0.0.0.0") == 0) {
                domain_mappings[domain_map_count].is_blocking = 1;
                if (inet_pton(AF_INET, ip_str, &domain_mappings[domain_map_count].ip_address) != 1) {
                    if (DEBUG_LEVEL > 0) fprintf(stderr, "�����ļ��� %d ��: ��������IP '%s' ʧ�� (���� %s)\n", line_num, ip_str, domain_str_from_file); continue;
                }
            }
            else {
                domain_mappings[domain_map_count].is_blocking = 0;
                if (inet_pton(AF_INET, ip_str, &domain_mappings[domain_map_count].ip_address) != 1) {
                    if (DEBUG_LEVEL > 0) fprintf(stderr, "�����ļ��� %d ��: ����IP '%s' ʧ�� (���� %s)\n", line_num, ip_str, domain_str_from_file); continue;
                }
            }
            strncpy(domain_mappings[domain_map_count].domain_name, domain_str_from_file, 255); domain_mappings[domain_map_count].domain_name[255] = '\0';
            if (DEBUG_LEVEL > 1) { char temp_ip_str[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &domain_mappings[domain_map_count].ip_address, temp_ip_str, INET_ADDRSTRLEN); printf("�Ѽ���: IP %s, ���� %s, ����: %d\n", temp_ip_str, domain_mappings[domain_map_count].domain_name, domain_mappings[domain_map_count].is_blocking); }
            domain_map_count++;
        }
        else {
            if (DEBUG_LEVEL > 0 && strlen(line) > 0) fprintf(stderr, "�����ļ��� %d �и�ʽ����: '%s'\n", line_num, line);
        }
    }
    fclose(file); if (DEBUG_LEVEL > 0) printf("�� %s ������ %d ������ӳ�䡣\n", CONFIG_FILENAME, domain_map_count);
}

// Ϊ�����������ұ���ӳ��
DomainEntry* find_local_mapping(const char* query_domain) { /* ... (����һ�汾��ͬ) ... */
    for (int i = 0; i < domain_map_count; i++) {
#ifdef _WIN32
        if (_stricmp(domain_mappings[i].domain_name, query_domain) == 0) { return &domain_mappings[i]; }
#else
        if (strcasecmp(domain_mappings[i].domain_name, query_domain) == 0) { return &domain_mappings[i]; }
#endif
    } return NULL;
}

// ��������м̵�IDӳ��
IdMapping* add_id_mapping(uint16_t original_id_net_order, struct sockaddr_in client_addr) { /* ... (����һ�汾��ͬ) ... */
    for (int i = 0; i < MAX_ID_MAPPINGS; i++) {
        if (!id_translation_table[i].active || (time(NULL) - id_translation_table[i].timestamp > UPSTREAM_TIMEOUT_SEC * 10)) {
            id_translation_table[i].original_id = original_id_net_order; id_translation_table[i].relayed_id = htons(next_relayed_id++);
            if (next_relayed_id < 1000 || next_relayed_id > 65000) next_relayed_id = 1000;
            id_translation_table[i].client_addr = client_addr; id_translation_table[i].timestamp = time(NULL); id_translation_table[i].active = 1;
            if (DEBUG_LEVEL > 1) { char client_ip_str_debug[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str_debug, INET_ADDRSTRLEN); printf("  ���IDӳ��: ԭʼ %u -> �м� %u (�ͻ��� %s:%d)\n", ntohs(original_id_net_order), ntohs(id_translation_table[i].relayed_id), client_ip_str_debug, ntohs(client_addr.sin_port)); }
            return &id_translation_table[i];
        }
    } if (DEBUG_LEVEL > 0) fprintf(stderr, "����: IDת����������\n"); return NULL;
}

// ͨ���м�ID����IDӳ��
IdMapping* find_mapping_by_relayed_id(uint16_t relayed_id_net_order) { /* ... (����һ�汾��ͬ) ... */
    for (int i = 0; i < MAX_ID_MAPPINGS; i++) {
        if (id_translation_table[i].active && id_translation_table[i].relayed_id == relayed_id_net_order) {
            if (time(NULL) - id_translation_table[i].timestamp > UPSTREAM_TIMEOUT_SEC * 2) {
                if (DEBUG_LEVEL > 1) printf("  �ҵ��м�ID %u ��ӳ�䣬���ѳ�ʱ�����Ϊ�������\n", ntohs(relayed_id_net_order));
                id_translation_table[i].active = 0; return NULL;
            }
            if (DEBUG_LEVEL > 1) printf("  �ҵ��м�ID %u ��ӳ�� (ԭʼ %u)��\n", ntohs(relayed_id_net_order), ntohs(id_translation_table[i].original_id));
            return &id_translation_table[i];
        }
    } return NULL;
}

// ���IDӳ��Ϊ���
void remove_id_mapping_by_relayed_id(uint16_t relayed_id_net_order) { /* ... (����һ�汾��ͬ) ... */
    for (int i = 0; i < MAX_ID_MAPPINGS; i++) {
        if (id_translation_table[i].active && id_translation_table[i].relayed_id == relayed_id_net_order) {
            id_translation_table[i].active = 0;
            if (DEBUG_LEVEL > 1) printf("  �Ƴ��� relayed_id %u (ԭʼID %u) ��ӳ�䡣\n", ntohs(relayed_id_net_order), ntohs(id_translation_table[i].original_id));
            return;
        }
    }
}

// --- ������ ---
int main(int argc, char* argv[]) {
    SOCKET server_sock;
    int last_winsock_error;

#ifdef _WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup ʧ��, Winsock ���صĴ������: %d\n", iResult);
        return 1;
    }
    last_winsock_error = WSAGetLastError();
    if (last_winsock_error != 0 && DEBUG_LEVEL > 0) {
        fprintf(stderr, "WSAStartup �ɹ���WSAGetLastError() ���ط���ֵ: %d (��¼)\n", last_winsock_error);
    }
#endif

    // ���������в���
    int arg_idx = 1;
    while (arg_idx < argc) { /* ... (����һ�汾��ͬ) ... */
        if (strcmp(argv[arg_idx], "-d") == 0) { if (DEBUG_LEVEL < 1) DEBUG_LEVEL = 1; arg_idx++; }
        else if (strcmp(argv[arg_idx], "-dd") == 0) { DEBUG_LEVEL = 2; arg_idx++; }
        else {
            struct sockaddr_in temp_addr_parse;
            if (inet_pton(AF_INET, argv[arg_idx], &temp_addr_parse.sin_addr) == 1) {
                strncpy(UPSTREAM_DNS_SERVER_IP, argv[arg_idx], sizeof(UPSTREAM_DNS_SERVER_IP) - 1); UPSTREAM_DNS_SERVER_IP[sizeof(UPSTREAM_DNS_SERVER_IP) - 1] = '\0';
            }
            else {
                strncpy(CONFIG_FILENAME, argv[arg_idx], sizeof(CONFIG_FILENAME) - 1); CONFIG_FILENAME[sizeof(CONFIG_FILENAME) - 1] = '\0';
            } arg_idx++;
        }
    }

    if (DEBUG_LEVEL > 0) { /* ... (����һ�汾��ͬ) ... */
        printf("DNS �м̷�����������...\n"); printf("���Լ���: %d\n", DEBUG_LEVEL);
        printf("���� DNS ������: %s\n", UPSTREAM_DNS_SERVER_IP); printf("�����ļ�: %s\n", CONFIG_FILENAME);
    }

    load_domain_mappings();

    server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_sock == INVALID_SOCKET) { /* ... (����һ�汾��ͬ����ϸ���󱨸�) ... */
#ifdef _WIN32
        last_winsock_error = WSAGetLastError(); fprintf(stderr, "�׽��ִ���ʧ��, Winsock �������: %d\n", last_winsock_error);
        char err_msg[256]; if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, last_winsock_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err_msg, sizeof(err_msg), NULL) != 0) { fprintf(stderr, "������Ϣ: %s\n", err_msg); }
        else { fprintf(stderr, "�޷���ȡ������� %d ��Ӧ�Ĵ�����Ϣ�ı���\n", last_winsock_error); }
        WSACleanup();
#else
        perror("�׽��ִ���ʧ��");
#endif
        return 1;
    }
    if (DEBUG_LEVEL > 0) printf("�������׽��ִ����ɹ���\n");

    struct sockaddr_in server_addr, client_addr_from;
    server_addr.sin_family = AF_INET; server_addr.sin_addr.s_addr = INADDR_ANY; server_addr.sin_port = htons(DNS_PORT);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) { /* ... (����һ�汾��ͬ����ϸ���󱨸�) ... */
#ifdef _WIN32
        last_winsock_error = WSAGetLastError(); fprintf(stderr, "��ʧ��, Winsock �������: %d\n", last_winsock_error);
        char err_msg[256]; if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, last_winsock_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err_msg, sizeof(err_msg), NULL) != 0) { fprintf(stderr, "������Ϣ: %s\n", err_msg); }
        else { fprintf(stderr, "�޷���ȡ������� %d ��Ӧ�Ĵ�����Ϣ�ı���\n", last_winsock_error); }
#else
        perror("��ʧ��");
#endif
        closesocket(server_sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    if (DEBUG_LEVEL > 0) printf("�Ѱ󶨵��˿� %d�����ڼ���...\n", DNS_PORT);

    unsigned char buffer[BUFFER_SIZE]; socklen_t client_addr_from_len = sizeof(client_addr_from);
    fd_set readfds; struct timeval tv;

    while (1) {
        FD_ZERO(&readfds); FD_SET(server_sock, &readfds);
        tv.tv_sec = 1; tv.tv_usec = 0;
        int activity = select(server_sock + 1, &readfds, NULL, NULL, &tv);
        if (activity < 0) { /* ... (����һ�汾��ͬ�Ĵ������Sleep/usleep) ... */
#ifdef _WIN32
            last_winsock_error = WSAGetLastError(); fprintf(stderr, "select ����, Winsock �������: %d\n", last_winsock_error); Sleep(100);
#else
            perror("select ����"); usleep(100000);
#endif
            continue;
        }
        time_t current_time_for_cleanup = time(NULL); /* ... (IDӳ����������һ�汾��ͬ) ... */
        for (int i = 0; i < MAX_ID_MAPPINGS; i++) { if (id_translation_table[i].active && (current_time_for_cleanup - id_translation_table[i].timestamp > UPSTREAM_TIMEOUT_SEC * 10)) { if (DEBUG_LEVEL > 0) printf("IDӳ�䳬ʱ���Ƴ� relayed_id %u (ԭʼID %u)\n", ntohs(id_translation_table[i].relayed_id), ntohs(id_translation_table[i].original_id)); id_translation_table[i].active = 0; } }

        if (FD_ISSET(server_sock, &readfds)) {
            int recv_len = recvfrom(server_sock, (char*)buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr_from, &client_addr_from_len);
            if (recv_len == SOCKET_ERROR) { /* ... (����һ�汾��ͬ�Ĵ�����) ... */
                if (DEBUG_LEVEL > 0) {
#ifdef _WIN32
                    last_winsock_error = WSAGetLastError(); fprintf(stderr, "recvfrom ����, Winsock �������: %d\n", last_winsock_error);
#else
                    perror("recvfrom ����");
#endif
                } continue;
            }

            if (recv_len > 0 && (size_t)recv_len >= sizeof(DnsHeader)) {
                DnsHeader* dns_msg_header = (DnsHeader*)buffer; unsigned char* qname_start_ptr = buffer + sizeof(DnsHeader); char parsed_qname_str[256];
                if ((size_t)recv_len < sizeof(DnsHeader) + 1 + sizeof(DnsQuestionTrailer)) { if (DEBUG_LEVEL > 0) fprintf(stderr, "���ݰ����̣��޷�������Ч�Ĳ�ѯ������: %d\n", recv_len); continue; }
                int qname_len_in_msg = dns_name_to_string(qname_start_ptr, parsed_qname_str, buffer, recv_len);
                if (qname_len_in_msg < 0 || (sizeof(DnsHeader) + qname_len_in_msg + sizeof(DnsQuestionTrailer) > (size_t)recv_len)) { if (DEBUG_LEVEL > 0) fprintf(stderr, "��������ʧ�ܻ����ݰ����Ȳ��� (qname_len: %d, recv_len: %d)���������ݰ���\n", qname_len_in_msg, recv_len); continue; }
                DnsQuestionTrailer* q_trailer = (DnsQuestionTrailer*)(qname_start_ptr + qname_len_in_msg);
                char client_ip_str[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &client_addr_from.sin_addr, client_ip_str, INET_ADDRSTRLEN);

                if (DEBUG_LEVEL > 0) { /* ... (����һ�汾��ͬ����־) ... */
                    printf("\n[%lld] �յ����� %s:%d �� %s (ID: %u)\n", (long long)time(NULL), client_ip_str, ntohs(client_addr_from.sin_port), (dns_msg_header->qr == 0 ? "��ѯ" : "��Ӧ"), ntohs(dns_msg_header->id));
                    if (dns_msg_header->qr == 0 && ntohs(dns_msg_header->qdcount) > 0) { printf("  ��ѯ����: %s (����: %u, ���: %u)\n", parsed_qname_str, ntohs(q_trailer->qtype), ntohs(q_trailer->qclass)); }
                }
                if (DEBUG_LEVEL > 1) { /* ... (����һ�汾��ͬ����ϸ��־) ... */
                    printf("  ���ݰ� (ǰ %d �ֽ� / �ܹ� %d �ֽ�):\n  ", recv_len > 64 ? 64 : recv_len, recv_len);
                    for (int k = 0; k < (recv_len > 64 ? 64 : recv_len); k++) { printf("%02X ", buffer[k]); if ((k + 1) % 16 == 0 && k + 1 < (recv_len > 64 ? 64 : recv_len)) printf("\n  "); } printf("\n");
                }

                // ======== ����һ��ͨ���м��߼�����Ӧ�ã� ========
                if (dns_msg_header->qr == 0 && ntohs(dns_msg_header->qdcount) > 0) {
                    DomainEntry* local_entry = NULL;
                    if (ntohs(q_trailer->qtype) == 1 && ntohs(q_trailer->qclass) == 1) { // ֻ�� A/IN ��ѯ���б��ز���
                        local_entry = find_local_mapping(parsed_qname_str);
                    }

                    if (local_entry) { // �����ҵ� (��Ȼ��A/IN��ѯ)
                        unsigned char response_buffer[BUFFER_SIZE]; int question_section_len = qname_len_in_msg + sizeof(DnsQuestionTrailer);
                        memcpy(response_buffer, buffer, sizeof(DnsHeader) + question_section_len);
                        DnsHeader* dns_response_header = (DnsHeader*)response_buffer;
                        dns_response_header->qr = 1; dns_response_header->aa = 1;

                        if (local_entry->is_blocking) {
                            dns_response_header->rcode = 3; dns_response_header->ancount = htons(0); dns_response_header->nscount = htons(0); dns_response_header->arcount = htons(0);
                            int response_len = sizeof(DnsHeader) + question_section_len;
                            sendto(server_sock, (char*)response_buffer, response_len, 0, (struct sockaddr*)&client_addr_from, client_addr_from_len);
                            if (DEBUG_LEVEL > 0) printf("  ���������� %s, �������ƴ��� (ID: %u)��\n", parsed_qname_str, ntohs(dns_response_header->id));
                        }
                        else {
                            dns_response_header->rcode = 0; dns_response_header->ancount = htons(1); dns_response_header->nscount = htons(0); dns_response_header->arcount = htons(0);
                            unsigned char* answer_ptr = response_buffer + sizeof(DnsHeader) + question_section_len;
                            *answer_ptr++ = 0xC0; *answer_ptr++ = 0x0C; // ָ��
                            DnsResourceRecordPreamble* rr_preamble = (DnsResourceRecordPreamble*)answer_ptr;
                            rr_preamble->type = htons(1); rr_preamble->class_rr = htons(1); rr_preamble->ttl = htonl(3600); rr_preamble->rdlength = htons(4);
                            answer_ptr += sizeof(DnsResourceRecordPreamble); memcpy(answer_ptr, &local_entry->ip_address.s_addr, 4);
                            int response_len = (answer_ptr + 4) - response_buffer;
                            sendto(server_sock, (char*)response_buffer, response_len, 0, (struct sockaddr*)&client_addr_from, client_addr_from_len);
                            if (DEBUG_LEVEL > 0) { char ip_buf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &local_entry->ip_address, ip_buf, INET_ADDRSTRLEN); printf("  �ӱ����ļ���Ӧ %s (ID: %u)��IPΪ %s��\n", parsed_qname_str, ntohs(dns_response_header->id), ip_buf); }
                        }
                    }
                    else { // ����δ�ҵ�A/IN��¼�����߲�ѯ������������ -> �м�
                        if (DEBUG_LEVEL > 0 && !(ntohs(q_trailer->qtype) == 1 && ntohs(q_trailer->qclass) == 1)) {
                            printf("  ��A/IN��ѯ����A/IN��ѯ������δ�ҵ� %s (����: %u)��׼���м̡�\n", parsed_qname_str, ntohs(q_trailer->qtype));
                        }
                        else if (DEBUG_LEVEL > 0) {
                            printf("  A/IN��ѯ %s ����δ�ҵ���׼���м̡�\n", parsed_qname_str);
                        }
                        IdMapping* mapping = add_id_mapping(dns_msg_header->id, client_addr_from);
                        if (mapping) {
                            DnsHeader* query_to_send_header = (DnsHeader*)buffer; query_to_send_header->id = mapping->relayed_id;
                            struct sockaddr_in upstream_addr; upstream_addr.sin_family = AF_INET; upstream_addr.sin_port = htons(DNS_PORT);
                            if (inet_pton(AF_INET, UPSTREAM_DNS_SERVER_IP, &upstream_addr.sin_addr) != 1) {
                                if (DEBUG_LEVEL > 0) fprintf(stderr, "����: ��Ч������DNS������IP��ַ %s\n", UPSTREAM_DNS_SERVER_IP);
                                remove_id_mapping_by_relayed_id(mapping->relayed_id); continue;
                            }
                            sendto(server_sock, (char*)buffer, recv_len, 0, (struct sockaddr*)&upstream_addr, sizeof(upstream_addr));
                            if (DEBUG_LEVEL > 0) printf("  �м̲�ѯ %s (���� %u) �� %s (ԭʼ ID: %u -> �м� ID: %u)��\n", parsed_qname_str, ntohs(q_trailer->qtype), UPSTREAM_DNS_SERVER_IP, ntohs(mapping->original_id), ntohs(mapping->relayed_id));
                        }
                    }
                }
                else if (dns_msg_header->qr == 1) { // ����Ӧ
                    IdMapping* mapping = find_mapping_by_relayed_id(dns_msg_header->id);
                    if (mapping) {
                        dns_msg_header->id = mapping->original_id;
                        sendto(server_sock, (char*)buffer, recv_len, 0, (struct sockaddr*)&mapping->client_addr, sizeof(mapping->client_addr));
                        if (DEBUG_LEVEL > 0) {
                            char original_client_ip_str[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &mapping->client_addr.sin_addr, original_client_ip_str, INET_ADDRSTRLEN);
                            printf("  �յ��������� %s ����Ӧ (�м� ID: %u), ��ת�����ͻ��� %s:%d (ԭʼ ID: %u)��\n", client_ip_str, ntohs(mapping->relayed_id), original_client_ip_str, ntohs(mapping->client_addr.sin_port), ntohs(mapping->original_id));
                        }
                        remove_id_mapping_by_relayed_id(mapping->relayed_id);
                    }
                    else {
                        if (DEBUG_LEVEL > 0) fprintf(stderr, "  �յ����� %s:%d ��δ����/δ֪��ӦID %u���Ѷ�����\n", client_ip_str, ntohs(client_addr_from.sin_port), ntohs(dns_msg_header->id));
                    }
                }
            }
            else if (recv_len == 0) { if (DEBUG_LEVEL > 0) printf("�յ�0�ֽ����ݱ���\n"); }
        }
    }

    closesocket(server_sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}