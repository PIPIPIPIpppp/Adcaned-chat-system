#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define BUFFER_SIZE 1024

void *receive_messages(void *arg) {
    int socket = *(int *)arg;
    char buffer[BUFFER_SIZE];
    int read_size;

    while ((read_size = recv(socket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
        printf("%s\n", buffer);
    }

    if (read_size == 0) {
        printf("服务器已断开连接\n");
        fflush(stdout);
    } else if (read_size == -1) {
        perror("接收失败");
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "用法: %s <服务器IP> <端口号>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int client_socket;
    struct sockaddr_in server_addr;
    pthread_t thread_id;
    char username[50];
    char message[BUFFER_SIZE];
    const char *server_ip = argv[1];
    int port = atoi(argv[2]);

    // 创建套接字
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("创建套接字失败");
        exit(EXIT_FAILURE);
    }

    // 准备 sockaddr_in 结构
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    // 连接到服务器
    printf("正在与服务器建立连接...\n");
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("连接失败");
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    printf("连接服务器成功\n");

    printf("请输入你的用户名: ");
    fgets(username, 50, stdin);
    username[strcspn(username, "\n")] = 0;

    // 发送用户名到服务器
    send(client_socket, username, strlen(username), 0);

    // 接收并显示当前在线用户
    char online_users[BUFFER_SIZE];
    recv(client_socket, online_users, BUFFER_SIZE, 0);
    printf("当前在线用户: %s\n", online_users);

    printf("欢迎来到聊天频道，现在已经可以开始发送消息了\n");

    // 创建线程接收消息
    if (pthread_create(&thread_id, NULL, receive_messages, (void *)&client_socket) < 0) {
        perror("无法创建线程");
        close(client_socket);
        return 1;
    }

    // 发送消息
    while (1) {
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = 0;
        send(client_socket, message, strlen(message), 0);
    }

    close(client_socket);
    return 0;
}

