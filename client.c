#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <cjson/cJSON.h>

#define BUFFER_SIZE 1024
#define SHA256_DIGEST_LENGTH 32
//base64
const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
static const int mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    encoded_data[*output_length] = '\0';
    return encoded_data;
}
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {
    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length + 1);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0) & 0xFF;
    }

    decoded_data[*output_length] = '\0';  // Make sure the string ends with a null terminator
    return decoded_data;
}
// Function to sign data using SHA256 and RSA key (it is unfinished)
unsigned char *sign_data() {
    int ret = 0;
    SHA256_CTX sha = SHA256_Init();
    ret = SHA256(data, strlen(data), SHA256_DIGEST_LENGTH);

    if(ret != 1){
        perror("Failed to SHA256 the data");
	}
}

EVP_PKEY generate_RSA_keys(){
    int ret = 0;
    RSA	*r = NULL;
	BIGNUM *bne = NULL;
    EVP_PKEY *pkeys;
    pkeys = EVP_PKEY_new();

    unsigned long e = 65537;
    
    //Generate keys
    bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
        perror("Failed to create BIGNUM");
	}

    r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
        perror("Failed to generate keys");
	}

    ret = EVP_PKEY_assign_RSA(pkeys, r);
    if(ret != 1){
        perror("Failed to assign RSA to EVP");
	}

    RSA_free(r);
    BN_free(bne);

    return pkeys;
}

void *send_messages(int client_socket, string message, int flags) {
    // Creating the JSON structure
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "signed_data");
    cJSON *data_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "data", data_obj);  // Empty data object
    int counter = 12345;
    cJSON_AddNumberToObject(root, "counter", counter);

    //Generate keys and extract public key
    EVP_PKEY *pkeys;
    pkeys = EVP_PKEY_new();
    pkeys = generate_RSA_keys;
    unsigned char *public_key;
    EVP_PKEY_get_raw_public_key(pkeys, public_key, 32);

    //When it is a hello message, the public key is added to data
    if(message == "hello"){
        cJSON_AddStringToObject(data_obj, "type", hello);
        cJSON_AddStringToObject(data_obj, "public_key", public_key);
    }

    //Turns counter to string
    char counter_str[10];
    snprintf(counter_str, sizeof(counter_str), "%d", counter);

    char *data_json_str = cJSON_Print(data_obj);  // Convert "data" object to JSON string
    size_t data_len = strlen(data_json_str) + strlen(counter_str);

    char *to_sign = (char *)malloc(data_len + 1);
    snprintf(to_sign, data_len + 1, "%s%s", data_json_str, counter_str);

    // Sign the data with a private key
    unsigned char *signature = sign_data((unsigned char *)to_sign);
    if (!signature) {
        fprintf(stderr, "Failed to sign data\n");
        return 1;
    }

    // Base64 encode the signature


    // return final JSON
    char *final_json_str[BUFFER_SIZE];
    final_json_str = cJSON_Print(root);
    send(client_socket, final_json_str, strlen(final_json_str), flags);
}

void *receive_messages(void *arg) {
    int socket = *(int *)arg;
    char buffer[BUFFER_SIZE];
    int read_size;

    while ((read_size = recv(socket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
        printf("%s\n", buffer);
    }

    if (read_size == 0) {
        printf("Server is disconnect\n");
        fflush(stdout);
    } else if (read_size == -1) {
        perror("Fail to recieve");
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <Server IP> <Port number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int client_socket;
    struct sockaddr_in server_addr;
    pthread_t thread_id;
    char username[50];
    char message[BUFFER_SIZE];
    const char *server_ip = argv[1];
    int port = atoi(argv[2]);

    // Set up
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    // Ready for sockaddr_in structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    // Connect to server
    printf("Connecting...\n");
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Fail connection");
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    printf("Successully connect\n");

    printf("Input username: ");
    fgets(username, 50, stdin);
    username[strcspn(username, "\n")] = 0;

    // Send username to the server
    send(client_socket, username, strlen(username), 0);

    // recieve and show the user
    char online_users[BUFFER_SIZE];
    recv(client_socket, online_users, BUFFER_SIZE, 0);
    printf("Current online: %s\n", online_users);

    //Send 'hello' message to server
    send_messages(client_socket, "hello", 0);

    printf("Welcome to the channel, ready to start chatting\n");

    //Create a thread to receive messages
    if (pthread_create(&thread_id, NULL, receive_messages, (void *)&client_socket) < 0) {
        perror("Unable to create thread");
        close(client_socket);
        return 1;
    }

    //Send message
    while (1) {
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = 0;
        send(client_socket, message, strlen(message), 0);
    }

    close(client_socket);
    return 0;
}
    close(client_socket);
    return 0;
}
