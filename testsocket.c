#include <stdio.h>
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")

int main() {
    WSADATA wsaData;
    int iResult;
    SOCKET test_sock = INVALID_SOCKET;
    int socket_error_code; // 单独变量存储socket错误

    printf("Attempting WSAStartup...\n");
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup 失败, 返回的错误代码: %d\n", iResult);
        return 1;
    }
    printf("WSAStartup 成功。\n");

    // 清除任何可能存在的先前错误
    WSASetLastError(0);
    int post_startup_error = WSAGetLastError(); // 应该为0，除非SetLastError本身失败
    if (post_startup_error != 0) {
        printf("WSAStartup 之后并尝试清除后，WSAGetLastError() 仍然返回: %d (这很奇怪)\n", post_startup_error);
    }
    else {
        printf("WSAStartup 之后并尝试清除后，WSAGetLastError() 返回 0 (正常)。\n");
    }


    printf("Attempting socket() creation...\n");
    test_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    socket_error_code = WSAGetLastError(); // 在 socket() 调用后立即获取错误码

    if (test_sock == INVALID_SOCKET) {
        fprintf(stderr, "socket() 调用失败。\n");
        // 直接打印我们捕获的 socket_error_code
        fprintf(stderr, "WSAGetLastError() 在 socket() 之后返回的 Winsock 错误代码: %d\n", socket_error_code);

        // 额外信息: 尝试将错误码转换为消息字符串
        char err_msg[256];
        if (FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            socket_error_code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            err_msg,
            sizeof(err_msg),
            NULL) != 0) {
            fprintf(stderr, "错误信息: %s\n", err_msg);
        }
        else {
            fprintf(stderr, "无法获取错误代码 %d 对应的错误信息。\n", socket_error_code);
        }

        perror("perror 报告的错误"); // 仍然打印 perror 以供参考

        WSACleanup();
        return 1;
    }

    printf("socket() 调用成功。套接字句柄: %llu\n", (unsigned long long)test_sock);
    closesocket(test_sock);
    WSACleanup();
    printf("测试完成。\n");
    return 0;
}