#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
    char username[50];
} Client;

typedef struct {
    int socket;
    int index;
} ThreadArg;

Client clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(const char *message) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", tm_info);

    char formatted_message[BUFFER_SIZE + 30];
    snprintf(formatted_message, sizeof(formatted_message), "%s - %s", time_str, message);

    pthread_mutex_lock(&log_mutex);
    FILE *log_file = fopen("chat.log", "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s\n", formatted_message);
        fclose(log_file);
    }
    pthread_mutex_unlock(&log_mutex);
}

void broadcast_message(const char *message, int sender_socket) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != sender_socket) {
            send(clients[i].socket, message, strlen(message), 0);
        }
    }
    pthread_mutex_unlock(&mutex);
    log_message(message);
}

void send_online_users(int new_client_socket) {
    char online_users[BUFFER_SIZE] = "";
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < client_count; i++) {
        strcat(online_users, clients[i].username);
        if (i < client_count - 1) {
            strcat(online_users, ", ");
        }
    }
    pthread_mutex_unlock(&mutex);
    send(new_client_socket, online_users, strlen(online_users), 0);
}

void *handle_client(void *arg) {
    ThreadArg *thread_arg = (ThreadArg *)arg;
    int client_socket = thread_arg->socket;
    int client_index = thread_arg->index;
    free(thread_arg);

    char buffer[BUFFER_SIZE];
    int read_size;

    // recieve username
    read_size = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (read_size <= 0) {
        close(client_socket);
        return NULL;
    }
    buffer[read_size] = '\0';
    pthread_mutex_lock(&mutex);
    strcpy(clients[client_index].username, buffer);
    clients[client_index].socket = client_socket;
    pthread_mutex_unlock(&mutex);

    printf("%s Online\n", buffer);

    char join_message[BUFFER_SIZE];
    snprintf(join_message, sizeof(join_message), "%s Join the chatting room", buffer);
    broadcast_message(join_message, client_socket);

    send_online_users(client_socket);

    while ((read_size = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char time_str[20];
        strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", tm_info);

        char formatted_message[BUFFER_SIZE + 50];
        snprintf(formatted_message, sizeof(formatted_message), "%s - %s: %s", clients[client_index].username, time_str, buffer);

        printf("Recive meesage from %s: %s\n", clients[client_index].username, buffer);

        broadcast_message(formatted_message, client_socket);
    }

    // Offline
    char leave_message[BUFFER_SIZE];
    snprintf(leave_message, sizeof(leave_message), "%s Leave the chattig room", clients[client_index].username);
    printf("%s\n", leave_message);
    broadcast_message(leave_message, client_socket);

    //remove client
    pthread_mutex_lock(&mutex);
    for (int i = client_index; i < client_count - 1; i++) {
        clients[i] = clients[i + 1];
    }
    client_count--;
    pthread_mutex_unlock(&mutex);

    close(client_socket);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <Port number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    pthread_t thread_id;
    int port = atoi(argv[1]);

    //set up socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Fail to set up sockect");
        exit(EXIT_FAILURE);
    }

    // Ready for sockaddr_in structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    //Bond
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Fail bonding");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    //monitor
    listen(server_socket, 3);

    printf("waitting for connection...\n");

    while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len))) {
        printf("connection recieved\n");

        ThreadArg *thread_arg = malloc(sizeof(ThreadArg));
        thread_arg->socket = client_socket;
        thread_arg->index = client_count;

        if (pthread_create(&thread_id, NULL, handle_client, thread_arg) < 0) {
            perror("Connect create Detaching threads");
            free(thread_arg);
            return 1;
        }

        pthread_mutex_lock(&mutex);
        client_count++;
        pthread_mutex_unlock(&mutex);

        // Detaching threads
        pthread_detach(thread_id);
    }

    if (client_socket < 0) {
        perror("Fail connection");
        return 1;
    }

    close(server_socket);
    return 0;
}

    close(server_socket);
    return 0;
}

