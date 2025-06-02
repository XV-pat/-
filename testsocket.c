#include <stdio.h>
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")

int main() {
    WSADATA wsaData;
    int iResult;
    SOCKET test_sock = INVALID_SOCKET;
    int socket_error_code; // ���������洢socket����

    printf("Attempting WSAStartup...\n");
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup ʧ��, ���صĴ������: %d\n", iResult);
        return 1;
    }
    printf("WSAStartup �ɹ���\n");

    // ����κο��ܴ��ڵ���ǰ����
    WSASetLastError(0);
    int post_startup_error = WSAGetLastError(); // Ӧ��Ϊ0������SetLastError����ʧ��
    if (post_startup_error != 0) {
        printf("WSAStartup ֮�󲢳��������WSAGetLastError() ��Ȼ����: %d (������)\n", post_startup_error);
    }
    else {
        printf("WSAStartup ֮�󲢳��������WSAGetLastError() ���� 0 (����)��\n");
    }


    printf("Attempting socket() creation...\n");
    test_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    socket_error_code = WSAGetLastError(); // �� socket() ���ú�������ȡ������

    if (test_sock == INVALID_SOCKET) {
        fprintf(stderr, "socket() ����ʧ�ܡ�\n");
        // ֱ�Ӵ�ӡ���ǲ���� socket_error_code
        fprintf(stderr, "WSAGetLastError() �� socket() ֮�󷵻ص� Winsock �������: %d\n", socket_error_code);

        // ������Ϣ: ���Խ�������ת��Ϊ��Ϣ�ַ���
        char err_msg[256];
        if (FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            socket_error_code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            err_msg,
            sizeof(err_msg),
            NULL) != 0) {
            fprintf(stderr, "������Ϣ: %s\n", err_msg);
        }
        else {
            fprintf(stderr, "�޷���ȡ������� %d ��Ӧ�Ĵ�����Ϣ��\n", socket_error_code);
        }

        perror("perror ����Ĵ���"); // ��Ȼ��ӡ perror �Թ��ο�

        WSACleanup();
        return 1;
    }

    printf("socket() ���óɹ����׽��־��: %llu\n", (unsigned long long)test_sock);
    closesocket(test_sock);
    WSACleanup();
    printf("������ɡ�\n");
    return 0;
}