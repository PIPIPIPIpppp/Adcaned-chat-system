#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <openssl/sha.h>

#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
    char username[50];
    char password_hash[SHA256_DIGEST_LENGTH]; // aray to hold hashed password
    char salt[16]; // for password
    int session_token[64]; // session handling
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

// creates a secure random salt
void create_salt(char *salt, size_t length) {
    RAND_bytes(salt, length); 
}

// store hash
void hash_pass_salted(const char *password, const char *salt, const char *hash) {
    char salted_pass[BUFFER_SIZE + 16];
    memcpy(salted_pass, password, strlen(password));
    memcpy(salted_pass + strlen(password) + salt, 16);

    SHA256(salted_pass, strlen (password) + 16, hash);
}

// create a session token after login
void generate_session_token(char *token, size_t length){
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand(time(NULL));
    for (size_t i = 0; i < length; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        token[i] = charset[key];
    }
    token[length] = '\0';
}

//validates session token
int validate_session (const char *token) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < client_count; i++){
        if (strcmp(clients[i]. session_token, token) == 0) {
            pthread_mutex_unlock(&mutex);
            return i; //valid session
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1; //invalid session
}    

//create salt and hash password and store username
int register_user(const char *username, const char *password, int client_index) {
    create_salt(clients[client_index].salt, 16);
    hash_pass_salted(password, clients[client_index].ssalt, clients[client_index].password_hash);
    strcpy(clients[client_index]. username, username);
    return 0;
}

int authenticate_user(const char *username, const char *password, char *session_token, int client_index) {
    char input_hash[SHA256_DIGEST_LENGTH];

    //find user
    for (int i = 0; i < client_count; i++) {
        if (strcmp(clients[i].username, username) == 0) {
            hash_pass_salted(password, clients[i].salt, input_hash);
            if (memcmp(clients[i].password_hash, input_hash, SHA256_DIGEST_LENGTH) == 0) {
                generate_session_token(clients[i]. session_token, 64);
                strcpy(session_token, clients[i].session_token);
                return i;
            }
            else {
                return -1; //incorrect password
            }
        }
    }
    return -1; //if user not found
}

//add logic to authenticate user when connecting
void *handle_client(void *arg) {
    ThreadArg * thread_arg = (ThreadArg *)arg;
    int client_socket = thread_arg->socket;
    int client_index = thread_Arg->index;
    free(thread_arg);

    char buffer[BUFFER_SIZE];
    char session_token[64];
    int read_size;

    //recieve user name nad password for login or registration
    read_size - recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (read_size <= 0) {
        close(client_socket);
        return NULL;
    }
    buffer[read_size] = '\0';

    char command[10], username[50], password[50];
    sscanf(buffer, "%s, %s, %s", command, username, password);

    if strcmp(command, "REGISTER" == 0) {
        if (register_user(username, password, client_index) == 0) {
            send(client_socket, "Registration successful", 24, 0);
        }
    else if (strcmp(command, "LOGIN") == 0) {
        if (authenticate_user(username, password, session_token, client_index) >= 0){
             send(client_socket, session_token, strlen(session_token), 0);
        }
        else {
            send(client_socket, "Authentication failed", 22, 0);
            close(client_socket);
            return NULL;
        }
    }
    //handling messagess and valoidate session token
    while ((read_size = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
        char received_token[64];
        sscanf(buffer, "%s", received_token);

        if (validate_session(received_token) < 0) {
            send(client_socket, "Invalid session", 16, 0);
            continue;
        }
    }
    //terminate session
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

