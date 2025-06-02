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
#include <strings.h> // 用于 strcasecmp (在某些系统上，例如Linux)
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

#define DNS_PORT 53
#define BUFFER_SIZE 512       // UDP DNS 数据包最大大小
#define MAX_DOMAIN_ENTRIES 2048
#define MAX_ID_MAPPINGS 256
#define UPSTREAM_TIMEOUT_SEC 2 // 上游 DNS 服务器超时时间为2秒

// --- 全局变量和配置 ---
int DEBUG_LEVEL = 0; // 0: 无, 1: 基本, 2: 详细
char UPSTREAM_DNS_SERVER_IP[16] = "202.106.0.20"; // 默认上游 DNS
char CONFIG_FILENAME[256] = "dnsrelay.txt";     // 默认配置文件

// --- DNS 结构体 (RFC1035 4.1) ---

// 头部节格式 (RFC1035 4.1.1)
#pragma pack(push, 1) // 精确打包
typedef struct {
    uint16_t id;       // 标识号

    uint8_t rd : 1;     //期望递归
    uint8_t tc : 1;     // 消息被截断
    uint8_t aa : 1;     // 权威答案
    uint8_t opcode : 4; // 操作码
    uint8_t qr : 1;     // 查询/响应标志 (0 表示查询, 1 表示响应)

    uint8_t rcode : 4;  // 响应码
    uint8_t z : 3;      // 保留字段
    uint8_t ra : 1;     // 递归可用

    uint16_t qdcount;  // 问题数
    uint16_t ancount;  // 回答资源记录数
    uint16_t nscount;  // 权威名称服务器数
    uint16_t arcount;  // 附加资源记录数
} DnsHeader;

// 问题节格式 (RFC1035 4.1.2)
typedef struct {
    // QNAME 是可变长度的, 单独处理
    uint16_t qtype;  // 查询类型
    uint16_t qclass; // 查询类
} DnsQuestionTrailer;

// 资源记录格式 (RFC1035 4.1.3 / 3.2.1)
typedef struct {
    // NAME (可变长度, 以00或指针结束)
    // TYPE
    // CLASS
    // TTL
    // RDLENGTH
    // RDATA (可变长度)
    uint16_t type;     // RR TYPE code
    uint16_t class_rr; // RR CLASS code
    uint32_t ttl;      // time interval that the resource record may be cached
    uint16_t rdlength; // length in octets of the RDATA field
    // RDATA follows
} DnsResourceRecordPreamble;
#pragma pack(pop)

// --- 本地域名映射 ---
typedef struct {
    char domain_name[256];
    struct in_addr ip_address;
    int is_blocking;
} DomainEntry;
DomainEntry domain_mappings[MAX_DOMAIN_ENTRIES];
int domain_map_count = 0;

// --- 用于中继的ID转换 ---
typedef struct {
    uint16_t original_id;
    uint16_t relayed_id;
    struct sockaddr_in client_addr;
    time_t timestamp;
    int active;
} IdMapping;
IdMapping id_translation_table[MAX_ID_MAPPINGS];
uint16_t next_relayed_id = 1000; // RFC1035 4.1.1 ID是一个16位标识符

// --- 辅助函数 ---

// 将 DNS 名称格式转换为字符串。返回从 dns_name_ptr 读取的 QNAME 的字节数。
// 此函数现在更准确地计算原始消息中QNAME所占用的字节数，包括指针。
int dns_name_to_string(const unsigned char* qname_in_message, char* out_str, const unsigned char* buffer_start, int buffer_len) {
    const unsigned char* p = qname_in_message; // 指向消息中QNAME开始位置的指针
    char* out_p = out_str;        // 指向输出字符串缓冲区的指针
    int len_in_message = 0;       // QNAME在消息中实际占用的长度
    int name_parsed_once = 0;     // 标记整个域名是否至少被部分解析（用于处理根域名"."）
    int hops = 0;                 // 防止指针循环

    if (!qname_in_message || !out_str || !buffer_start || buffer_len <= 0) return -1;
    if (qname_in_message < buffer_start || qname_in_message >= buffer_start + buffer_len) return -1;

    *out_p = '\0'; // 初始化输出字符串为空

    while (*p != 0 && hops < 10) { // 最多10次指针跳转
        if (p < buffer_start || p >= buffer_start + buffer_len) { // 越界检查
            if (DEBUG_LEVEL > 0) fprintf(stderr, "错误: dns_name_to_string 中指针越界 (p)。\n"); return -1;
        }
        name_parsed_once = 1;
        if ((*p & 0xC0) == 0xC0) { // 是指针 RFC1035 4.1.4 [cite: 518, 1400]
            if (p + 1 >= buffer_start + buffer_len) { // 指针本身需要2字节
                if (DEBUG_LEVEL > 0) fprintf(stderr, "错误: dns_name_to_string 中指针不完整。\n"); return -1;
            }
            uint16_t offset = ntohs(*(uint16_t*)p) & 0x3FFF;
            if (len_in_message == 0) { // 如果这是QNAME的开始，则QNAME在消息中占用2字节
                len_in_message = 2;
            } // 如果不是开始（即标签后跟指针），则指针的长度已包含在之前标签的len_in_message计算中 (因为会读到指针)
              // 或者说，如果一个标签序列后紧跟一个指针，那么这个指针的2字节会替代那个标签序列末尾的0字节。
              // 此处简化：如果QNAME以指针开始，则长度为2。如果QNAME是标签序列+指针，则len_in_message会在循环结束时是标签序列+指针的长度。

            if (buffer_start + offset >= buffer_start + buffer_len) {
                if (DEBUG_LEVEL > 0) fprintf(stderr, "错误: dns_name_to_string 中指针偏移 (0x%X) 越界。\n", offset); return -1;
            }
            p = buffer_start + offset; // 跳转
            hops++;
            // 在跳转后，如果输出字符串已有内容且不是以'.'结尾，则添加'.'
            if (out_p != out_str && *(out_p - 1) != '.' && *p != 0) {
                *out_p++ = '.';
            }
            continue; // 从新位置继续解析
        }
        else { // 是标签
            uint8_t label_len = *p;
            if (label_len > 63) {
                if (DEBUG_LEVEL > 0) fprintf(stderr, "错误: DNS标签长度 (0x%X) 非法 (>63)。\n", label_len); return -1;
            }
            // 检查标签长度+数据是否越界
            if (p + 1 + label_len >= buffer_start + buffer_len + 1) { // p+1+label_len是下一个标签的开始或结尾的0
                if (DEBUG_LEVEL > 0) fprintf(stderr, "错误: DNS标签数据 (长度 %u @ %td) 将超出缓冲区 (总长 %d)。\n", label_len, p - buffer_start, buffer_len); return -1;
            }

            if (len_in_message == 0 || (qname_in_message + len_in_message != p)) {
                // 如果len_in_message为0（首次），或者当前p的位置不是紧接着上次记录的len_in_message之后（说明经过了指针跳转）
                // 那么我们只计算当前正在解析的、非指针部分的长度
                // 这一部分的假设是，len_in_message只记录从qname_in_message开始的连续字节数
            }


            p++; // 跳过长度字节
            // 如果不是输出的第一个标签段，并且之前没有写入点，则添加点
            if (out_p != out_str && *(out_p - 1) != '.') {
                *out_p++ = '.';
            }
            memcpy(out_p, p, label_len);
            p += label_len;
            out_p += label_len;
        }
    }
    *out_p = '\0'; // 字符串结束

    // 计算QNAME在消息中的实际长度
    // 如果整个qname_in_message就是一个0 (根域名)
    if (*qname_in_message == 0 && !name_parsed_once) {
        return 1;
    }
    // 否则，长度是从 qname_in_message 到当前 p 指针（它指向结尾的0或指针）的距离
    // 但如果中间有指针，实际长度是首次遇到指针时的位置 + 2
    // 这个函数的目标是算出 qname_in_message 在原数据包里占了多少字节
    // 最简单的方法是，从qname_in_message开始扫描，直到遇到0或者一个指针的末尾
    const unsigned char* scanner = qname_in_message;
    while (scanner < buffer_start + buffer_len) {
        if ((*scanner & 0xC0) == 0xC0) { // 是指针
            len_in_message = (scanner - qname_in_message) + 2;
            goto end_len_calc;
        }
        else if (*scanner == 0) { // 是结尾0
            len_in_message = (scanner - qname_in_message) + 1;
            goto end_len_calc;
        }
        else { // 是标签长度
            uint8_t l = *scanner;
            if (l > 63 || scanner + 1 + l >= buffer_start + buffer_len + 1) { return -1; /* 格式错误 */ }
            scanner += (1 + l);
        }
    }
    return -1; // 如果循环结束还没找到结尾，说明格式错误或超出buffer_len

end_len_calc:
    if (hops >= 10 && DEBUG_LEVEL > 0) fprintf(stderr, "警告：解析域名时指针跳转过多，可能存在循环。\n");
    return len_in_message;
}


// 将字符串转换为DNS名称格式。返回DNS格式名称的长度。
int string_to_dns_name(const char* str_name, unsigned char* out_dns_name) { /* ... (与上一版本相同) ... */
    char name_copy[256]; strncpy(name_copy, str_name, 255); name_copy[255] = '\0';
    unsigned char* dns_ptr = out_dns_name; char* token = strtok(name_copy, "."); int total_len = 0;
    while (token != NULL) {
        uint8_t len = strlen(token); if (len > 63) { if (DEBUG_LEVEL > 0) fprintf(stderr, "错误: 域名标签 '%s' 过长 (>63字节)。\n", token); return -1; }
        *dns_ptr++ = len; memcpy(dns_ptr, token, len); dns_ptr += len; total_len += (len + 1); token = strtok(NULL, ".");
    }
    *dns_ptr = 0; total_len += 1;
    if (total_len > 255) { if (DEBUG_LEVEL > 0) fprintf(stderr, "错误: 转换后的DNS域名总长度 %d 过长 (>255字节)。\n", total_len); return -1; }
    return total_len;
}

// 从配置文件加载域名映射
void load_domain_mappings() { /* ... (与上一版本相同) ... */
    FILE* file = fopen(CONFIG_FILENAME, "r");
    if (!file) {
        if (DEBUG_LEVEL > 0) fprintf(stderr, "警告: 打开配置文件 '%s' 失败。", CONFIG_FILENAME);
#ifdef _WIN32
        if (DEBUG_LEVEL > 0) { char errBuf[256]; DWORD dwError = GetLastError(); FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errBuf, sizeof(errBuf), NULL); fprintf(stderr, " 系统错误代码 %lu: %s\n", dwError, errBuf); }
#else
        if (DEBUG_LEVEL > 0) perror(" 系统错误");
#endif
        if (DEBUG_LEVEL > 0) fprintf(stderr, "将不使用本地域名解析。\n"); return;
    }
    char line[512]; int line_num = 0; domain_map_count = 0;
    while (fgets(line, sizeof(line), file) && domain_map_count < MAX_DOMAIN_ENTRIES) {
        line_num++; char ip_str[100]; char domain_str_from_file[256];
        line[strcspn(line, "\r\n")] = 0; if (line[0] == '\0' || line[0] == '#' || line[0] == ';') continue;
        if (sscanf(line, "%99s %255s", ip_str, domain_str_from_file) == 2) {
            if (strcmp(ip_str, "0.0.0.0") == 0) {
                domain_mappings[domain_map_count].is_blocking = 1;
                if (inet_pton(AF_INET, ip_str, &domain_mappings[domain_map_count].ip_address) != 1) {
                    if (DEBUG_LEVEL > 0) fprintf(stderr, "配置文件第 %d 行: 解析拦截IP '%s' 失败 (域名 %s)\n", line_num, ip_str, domain_str_from_file); continue;
                }
            }
            else {
                domain_mappings[domain_map_count].is_blocking = 0;
                if (inet_pton(AF_INET, ip_str, &domain_mappings[domain_map_count].ip_address) != 1) {
                    if (DEBUG_LEVEL > 0) fprintf(stderr, "配置文件第 %d 行: 解析IP '%s' 失败 (域名 %s)\n", line_num, ip_str, domain_str_from_file); continue;
                }
            }
            strncpy(domain_mappings[domain_map_count].domain_name, domain_str_from_file, 255); domain_mappings[domain_map_count].domain_name[255] = '\0';
            if (DEBUG_LEVEL > 1) { char temp_ip_str[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &domain_mappings[domain_map_count].ip_address, temp_ip_str, INET_ADDRSTRLEN); printf("已加载: IP %s, 域名 %s, 拦截: %d\n", temp_ip_str, domain_mappings[domain_map_count].domain_name, domain_mappings[domain_map_count].is_blocking); }
            domain_map_count++;
        }
        else {
            if (DEBUG_LEVEL > 0 && strlen(line) > 0) fprintf(stderr, "配置文件第 %d 行格式错误: '%s'\n", line_num, line);
        }
    }
    fclose(file); if (DEBUG_LEVEL > 0) printf("从 %s 加载了 %d 条域名映射。\n", CONFIG_FILENAME, domain_map_count);
}

// 为给定域名查找本地映射
DomainEntry* find_local_mapping(const char* query_domain) { /* ... (与上一版本相同) ... */
    for (int i = 0; i < domain_map_count; i++) {
#ifdef _WIN32
        if (_stricmp(domain_mappings[i].domain_name, query_domain) == 0) { return &domain_mappings[i]; }
#else
        if (strcasecmp(domain_mappings[i].domain_name, query_domain) == 0) { return &domain_mappings[i]; }
#endif
    } return NULL;
}

// 添加用于中继的ID映射
IdMapping* add_id_mapping(uint16_t original_id_net_order, struct sockaddr_in client_addr) { /* ... (与上一版本相同) ... */
    for (int i = 0; i < MAX_ID_MAPPINGS; i++) {
        if (!id_translation_table[i].active || (time(NULL) - id_translation_table[i].timestamp > UPSTREAM_TIMEOUT_SEC * 10)) {
            id_translation_table[i].original_id = original_id_net_order; id_translation_table[i].relayed_id = htons(next_relayed_id++);
            if (next_relayed_id < 1000 || next_relayed_id > 65000) next_relayed_id = 1000;
            id_translation_table[i].client_addr = client_addr; id_translation_table[i].timestamp = time(NULL); id_translation_table[i].active = 1;
            if (DEBUG_LEVEL > 1) { char client_ip_str_debug[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str_debug, INET_ADDRSTRLEN); printf("  添加ID映射: 原始 %u -> 中继 %u (客户端 %s:%d)\n", ntohs(original_id_net_order), ntohs(id_translation_table[i].relayed_id), client_ip_str_debug, ntohs(client_addr.sin_port)); }
            return &id_translation_table[i];
        }
    } if (DEBUG_LEVEL > 0) fprintf(stderr, "错误: ID转换表已满。\n"); return NULL;
}

// 通过中继ID查找ID映射
IdMapping* find_mapping_by_relayed_id(uint16_t relayed_id_net_order) { /* ... (与上一版本相同) ... */
    for (int i = 0; i < MAX_ID_MAPPINGS; i++) {
        if (id_translation_table[i].active && id_translation_table[i].relayed_id == relayed_id_net_order) {
            if (time(NULL) - id_translation_table[i].timestamp > UPSTREAM_TIMEOUT_SEC * 2) {
                if (DEBUG_LEVEL > 1) printf("  找到中继ID %u 的映射，但已超时（标记为不活动）。\n", ntohs(relayed_id_net_order));
                id_translation_table[i].active = 0; return NULL;
            }
            if (DEBUG_LEVEL > 1) printf("  找到中继ID %u 的映射 (原始 %u)。\n", ntohs(relayed_id_net_order), ntohs(id_translation_table[i].original_id));
            return &id_translation_table[i];
        }
    } return NULL;
}

// 标记ID映射为不活动
void remove_id_mapping_by_relayed_id(uint16_t relayed_id_net_order) { /* ... (与上一版本相同) ... */
    for (int i = 0; i < MAX_ID_MAPPINGS; i++) {
        if (id_translation_table[i].active && id_translation_table[i].relayed_id == relayed_id_net_order) {
            id_translation_table[i].active = 0;
            if (DEBUG_LEVEL > 1) printf("  移除了 relayed_id %u (原始ID %u) 的映射。\n", ntohs(relayed_id_net_order), ntohs(id_translation_table[i].original_id));
            return;
        }
    }
}

// --- 主程序 ---
int main(int argc, char* argv[]) {
    SOCKET server_sock;
    int last_winsock_error;

#ifdef _WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup 失败, Winsock 返回的错误代码: %d\n", iResult);
        return 1;
    }
    last_winsock_error = WSAGetLastError();
    if (last_winsock_error != 0 && DEBUG_LEVEL > 0) {
        fprintf(stderr, "WSAStartup 成功后，WSAGetLastError() 返回非零值: %d (记录)\n", last_winsock_error);
    }
#endif

    // 解析命令行参数
    int arg_idx = 1;
    while (arg_idx < argc) { /* ... (与上一版本相同) ... */
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

    if (DEBUG_LEVEL > 0) { /* ... (与上一版本相同) ... */
        printf("DNS 中继服务器启动中...\n"); printf("调试级别: %d\n", DEBUG_LEVEL);
        printf("上游 DNS 服务器: %s\n", UPSTREAM_DNS_SERVER_IP); printf("配置文件: %s\n", CONFIG_FILENAME);
    }

    load_domain_mappings();

    server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_sock == INVALID_SOCKET) { /* ... (与上一版本相同的详细错误报告) ... */
#ifdef _WIN32
        last_winsock_error = WSAGetLastError(); fprintf(stderr, "套接字创建失败, Winsock 错误代码: %d\n", last_winsock_error);
        char err_msg[256]; if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, last_winsock_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err_msg, sizeof(err_msg), NULL) != 0) { fprintf(stderr, "错误信息: %s\n", err_msg); }
        else { fprintf(stderr, "无法获取错误代码 %d 对应的错误信息文本。\n", last_winsock_error); }
        WSACleanup();
#else
        perror("套接字创建失败");
#endif
        return 1;
    }
    if (DEBUG_LEVEL > 0) printf("服务器套接字创建成功。\n");

    struct sockaddr_in server_addr, client_addr_from;
    server_addr.sin_family = AF_INET; server_addr.sin_addr.s_addr = INADDR_ANY; server_addr.sin_port = htons(DNS_PORT);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) { /* ... (与上一版本相同的详细错误报告) ... */
#ifdef _WIN32
        last_winsock_error = WSAGetLastError(); fprintf(stderr, "绑定失败, Winsock 错误代码: %d\n", last_winsock_error);
        char err_msg[256]; if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, last_winsock_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err_msg, sizeof(err_msg), NULL) != 0) { fprintf(stderr, "错误信息: %s\n", err_msg); }
        else { fprintf(stderr, "无法获取错误代码 %d 对应的错误信息文本。\n", last_winsock_error); }
#else
        perror("绑定失败");
#endif
        closesocket(server_sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    if (DEBUG_LEVEL > 0) printf("已绑定到端口 %d，正在监听...\n", DNS_PORT);

    unsigned char buffer[BUFFER_SIZE]; socklen_t client_addr_from_len = sizeof(client_addr_from);
    fd_set readfds; struct timeval tv;

    while (1) {
        FD_ZERO(&readfds); FD_SET(server_sock, &readfds);
        tv.tv_sec = 1; tv.tv_usec = 0;
        int activity = select(server_sock + 1, &readfds, NULL, NULL, &tv);
        if (activity < 0) { /* ... (与上一版本相同的错误处理和Sleep/usleep) ... */
#ifdef _WIN32
            last_winsock_error = WSAGetLastError(); fprintf(stderr, "select 错误, Winsock 错误代码: %d\n", last_winsock_error); Sleep(100);
#else
            perror("select 错误"); usleep(100000);
#endif
            continue;
        }
        time_t current_time_for_cleanup = time(NULL); /* ... (ID映射清理与上一版本相同) ... */
        for (int i = 0; i < MAX_ID_MAPPINGS; i++) { if (id_translation_table[i].active && (current_time_for_cleanup - id_translation_table[i].timestamp > UPSTREAM_TIMEOUT_SEC * 10)) { if (DEBUG_LEVEL > 0) printf("ID映射超时，移除 relayed_id %u (原始ID %u)\n", ntohs(id_translation_table[i].relayed_id), ntohs(id_translation_table[i].original_id)); id_translation_table[i].active = 0; } }

        if (FD_ISSET(server_sock, &readfds)) {
            int recv_len = recvfrom(server_sock, (char*)buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr_from, &client_addr_from_len);
            if (recv_len == SOCKET_ERROR) { /* ... (与上一版本相同的错误处理) ... */
                if (DEBUG_LEVEL > 0) {
#ifdef _WIN32
                    last_winsock_error = WSAGetLastError(); fprintf(stderr, "recvfrom 错误, Winsock 错误代码: %d\n", last_winsock_error);
#else
                    perror("recvfrom 错误");
#endif
                } continue;
            }

            if (recv_len > 0 && (size_t)recv_len >= sizeof(DnsHeader)) {
                DnsHeader* dns_msg_header = (DnsHeader*)buffer; unsigned char* qname_start_ptr = buffer + sizeof(DnsHeader); char parsed_qname_str[256];
                if ((size_t)recv_len < sizeof(DnsHeader) + 1 + sizeof(DnsQuestionTrailer)) { if (DEBUG_LEVEL > 0) fprintf(stderr, "数据包过短，无法包含有效的查询。长度: %d\n", recv_len); continue; }
                int qname_len_in_msg = dns_name_to_string(qname_start_ptr, parsed_qname_str, buffer, recv_len);
                if (qname_len_in_msg < 0 || (sizeof(DnsHeader) + qname_len_in_msg + sizeof(DnsQuestionTrailer) > (size_t)recv_len)) { if (DEBUG_LEVEL > 0) fprintf(stderr, "域名解析失败或数据包长度不足 (qname_len: %d, recv_len: %d)，丢弃数据包。\n", qname_len_in_msg, recv_len); continue; }
                DnsQuestionTrailer* q_trailer = (DnsQuestionTrailer*)(qname_start_ptr + qname_len_in_msg);
                char client_ip_str[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &client_addr_from.sin_addr, client_ip_str, INET_ADDRSTRLEN);

                if (DEBUG_LEVEL > 0) { /* ... (与上一版本相同的日志) ... */
                    printf("\n[%lld] 收到来自 %s:%d 的 %s (ID: %u)\n", (long long)time(NULL), client_ip_str, ntohs(client_addr_from.sin_port), (dns_msg_header->qr == 0 ? "查询" : "响应"), ntohs(dns_msg_header->id));
                    if (dns_msg_header->qr == 0 && ntohs(dns_msg_header->qdcount) > 0) { printf("  查询域名: %s (类型: %u, 类别: %u)\n", parsed_qname_str, ntohs(q_trailer->qtype), ntohs(q_trailer->qclass)); }
                }
                if (DEBUG_LEVEL > 1) { /* ... (与上一版本相同的详细日志) ... */
                    printf("  数据包 (前 %d 字节 / 总共 %d 字节):\n  ", recv_len > 64 ? 64 : recv_len, recv_len);
                    for (int k = 0; k < (recv_len > 64 ? 64 : recv_len); k++) { printf("%02X ", buffer[k]); if ((k + 1) % 16 == 0 && k + 1 < (recv_len > 64 ? 64 : recv_len)) printf("\n  "); } printf("\n");
                }

                // ======== 方案一：通用中继逻辑（已应用） ========
                if (dns_msg_header->qr == 0 && ntohs(dns_msg_header->qdcount) > 0) {
                    DomainEntry* local_entry = NULL;
                    if (ntohs(q_trailer->qtype) == 1 && ntohs(q_trailer->qclass) == 1) { // 只对 A/IN 查询进行本地查找
                        local_entry = find_local_mapping(parsed_qname_str);
                    }

                    if (local_entry) { // 本地找到 (必然是A/IN查询)
                        unsigned char response_buffer[BUFFER_SIZE]; int question_section_len = qname_len_in_msg + sizeof(DnsQuestionTrailer);
                        memcpy(response_buffer, buffer, sizeof(DnsHeader) + question_section_len);
                        DnsHeader* dns_response_header = (DnsHeader*)response_buffer;
                        dns_response_header->qr = 1; dns_response_header->aa = 1;

                        if (local_entry->is_blocking) {
                            dns_response_header->rcode = 3; dns_response_header->ancount = htons(0); dns_response_header->nscount = htons(0); dns_response_header->arcount = htons(0);
                            int response_len = sizeof(DnsHeader) + question_section_len;
                            sendto(server_sock, (char*)response_buffer, response_len, 0, (struct sockaddr*)&client_addr_from, client_addr_from_len);
                            if (DEBUG_LEVEL > 0) printf("  已拦截域名 %s, 发送名称错误 (ID: %u)。\n", parsed_qname_str, ntohs(dns_response_header->id));
                        }
                        else {
                            dns_response_header->rcode = 0; dns_response_header->ancount = htons(1); dns_response_header->nscount = htons(0); dns_response_header->arcount = htons(0);
                            unsigned char* answer_ptr = response_buffer + sizeof(DnsHeader) + question_section_len;
                            *answer_ptr++ = 0xC0; *answer_ptr++ = 0x0C; // 指针
                            DnsResourceRecordPreamble* rr_preamble = (DnsResourceRecordPreamble*)answer_ptr;
                            rr_preamble->type = htons(1); rr_preamble->class_rr = htons(1); rr_preamble->ttl = htonl(3600); rr_preamble->rdlength = htons(4);
                            answer_ptr += sizeof(DnsResourceRecordPreamble); memcpy(answer_ptr, &local_entry->ip_address.s_addr, 4);
                            int response_len = (answer_ptr + 4) - response_buffer;
                            sendto(server_sock, (char*)response_buffer, response_len, 0, (struct sockaddr*)&client_addr_from, client_addr_from_len);
                            if (DEBUG_LEVEL > 0) { char ip_buf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &local_entry->ip_address, ip_buf, INET_ADDRSTRLEN); printf("  从本地文件响应 %s (ID: %u)，IP为 %s。\n", parsed_qname_str, ntohs(dns_response_header->id), ip_buf); }
                        }
                    }
                    else { // 本地未找到A/IN记录，或者查询的是其他类型 -> 中继
                        if (DEBUG_LEVEL > 0 && !(ntohs(q_trailer->qtype) == 1 && ntohs(q_trailer->qclass) == 1)) {
                            printf("  非A/IN查询，或A/IN查询但本地未找到 %s (类型: %u)，准备中继。\n", parsed_qname_str, ntohs(q_trailer->qtype));
                        }
                        else if (DEBUG_LEVEL > 0) {
                            printf("  A/IN查询 %s 本地未找到，准备中继。\n", parsed_qname_str);
                        }
                        IdMapping* mapping = add_id_mapping(dns_msg_header->id, client_addr_from);
                        if (mapping) {
                            DnsHeader* query_to_send_header = (DnsHeader*)buffer; query_to_send_header->id = mapping->relayed_id;
                            struct sockaddr_in upstream_addr; upstream_addr.sin_family = AF_INET; upstream_addr.sin_port = htons(DNS_PORT);
                            if (inet_pton(AF_INET, UPSTREAM_DNS_SERVER_IP, &upstream_addr.sin_addr) != 1) {
                                if (DEBUG_LEVEL > 0) fprintf(stderr, "错误: 无效的上游DNS服务器IP地址 %s\n", UPSTREAM_DNS_SERVER_IP);
                                remove_id_mapping_by_relayed_id(mapping->relayed_id); continue;
                            }
                            sendto(server_sock, (char*)buffer, recv_len, 0, (struct sockaddr*)&upstream_addr, sizeof(upstream_addr));
                            if (DEBUG_LEVEL > 0) printf("  中继查询 %s (类型 %u) 到 %s (原始 ID: %u -> 中继 ID: %u)。\n", parsed_qname_str, ntohs(q_trailer->qtype), UPSTREAM_DNS_SERVER_IP, ntohs(mapping->original_id), ntohs(mapping->relayed_id));
                        }
                    }
                }
                else if (dns_msg_header->qr == 1) { // 是响应
                    IdMapping* mapping = find_mapping_by_relayed_id(dns_msg_header->id);
                    if (mapping) {
                        dns_msg_header->id = mapping->original_id;
                        sendto(server_sock, (char*)buffer, recv_len, 0, (struct sockaddr*)&mapping->client_addr, sizeof(mapping->client_addr));
                        if (DEBUG_LEVEL > 0) {
                            char original_client_ip_str[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &mapping->client_addr.sin_addr, original_client_ip_str, INET_ADDRSTRLEN);
                            printf("  收到来自上游 %s 的响应 (中继 ID: %u), 已转发给客户端 %s:%d (原始 ID: %u)。\n", client_ip_str, ntohs(mapping->relayed_id), original_client_ip_str, ntohs(mapping->client_addr.sin_port), ntohs(mapping->original_id));
                        }
                        remove_id_mapping_by_relayed_id(mapping->relayed_id);
                    }
                    else {
                        if (DEBUG_LEVEL > 0) fprintf(stderr, "  收到来自 %s:%d 的未请求/未知响应ID %u。已丢弃。\n", client_ip_str, ntohs(client_addr_from.sin_port), ntohs(dns_msg_header->id));
                    }
                }
            }
            else if (recv_len == 0) { if (DEBUG_LEVEL > 0) printf("收到0字节数据报。\n"); }
        }
    }

    closesocket(server_sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}