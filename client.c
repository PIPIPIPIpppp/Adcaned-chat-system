#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <cjson/cJSON.h>

#ifdef _WIN32  // Windows
    #include <winsock2.h>
    #include <Ws2tcpip.h>
    #include <windows.h>
    typedef HANDLE pthread_t;
    #pragma comment(lib, "Ws2_32.lib")
#else  // Linux/Unix
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <pthread.h>
#endif                         

#define BUFFER_SIZE 1024
#define SHA256_DIGEST_LENGTH 32
//base64
const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
static const int mod_table[] = {0, 2, 1};

typedef struct {
    char **server_list;   // Array of server addresses
    char ***key_list;     // 2D Array of client keys (per server)
    int server_count;     // Number of servers
} ClientInfo;

char *base64_encode(const unsigned char *data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(output_length + 1);
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
        encoded_data[output_length - 1 - i] = '=';

    encoded_data[output_length] = '\0';
    return encoded_data;
}

unsigned char *base64_decode(const char *data, size_t input_length) {
    if (input_length % 4 != 0) return NULL;

    size_t output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (output_length)--;
    if (data[input_length - 2] == '=') (output_length)--;

    unsigned char *decoded_data = malloc(output_length + 1);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : strchr(base64_chars, data[i++]) - base64_chars;

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 0) & 0xFF;
    }                                                                                                                                      

    decoded_data[output_length] = '\0';  // Make sure the string ends with a null terminator
    return decoded_data;
}

// Function to sign data using SHA256 and RSA key
unsigned char *sign_data(EVP_PKEY *private_key, const unsigned char *data_counter, size_t data_len) {
    int ret = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned char *signature = malloc(EVP_PKEY_size(private_key));

    EVP_SignInit(mdctx, EVP_sha256());
    EVP_SignUpdate(mdctx, data_counter, data_len);
    if (EVP_SignFinal(mdctx, signature, 32, private_key) != 1) {
        free(signature);
        EVP_MD_CTX_free(mdctx);
        perror("Failed to create signature");
        return NULL; // Error
    }

    EVP_MD_CTX_free(mdctx);
    return signature;
}

//Function to create the fingerprint from the RSA public key
unsigned char *create_fingerprint(EVP_PKEY *public_key){
    //Export the public key to PEM format
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, public_key);
    
    //Get the length of the PEM data
    size_t pem_length = BIO_ctrl_pending(bio);
    char *pem_key = (char *)malloc(pem_length + 1);
    BIO_read(bio, pem_key, pem_length);
    pem_key[pem_length] = '\0'; // Null-terminate

    //Hash the PEM key using SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)pem_key, strlen(pem_key), hash);

    //Base64 encode the hash to create the fingerprint
    size_t input_length = SHA256_DIGEST_LENGTH;
    unsigned char *fingerprint = base64_encode(hash, input_length);

    BIO_free(bio);
    free(pem_key);

    return fingerprint;
}

EVP_PKEY *generate_RSA_keys(){
    int ret = 0;
    RSA	*r = NULL;
	BIGNUM *bne = NULL;
    EVP_PKEY *pkeys;
    pkeys = EVP_PKEY_new();

    unsigned long e = 65537;
    int bits = 2048;  //key length

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

int AES_Encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag){
    EVP_CIPHER_CTX *ctx;
    int plaintext_len = strlen((char*) plaintext);
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new(); //Create the context

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL); //Setting IV Length to 16 bytes

    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv); //Initialise the Encryption

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len); //Encrypt the plaintext
    ciphertext_len = len;
    
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); //Finalize encryption
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag); //Get the tag

    EVP_CIPHER_CTX_free(ctx); //Clean up

    return ciphertext_len;
}

void *send_messages(int client_socket, char *message, char messageType, char recipients, ClientInfo client_info, int flags) {
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
    pkeys = generate_RSA_keys();
    unsigned char *public_key;
    EVP_PKEY_get_raw_public_key(pkeys, public_key, 32);

    //Get list of recipients info
    ClientInfo *info = receive_client_list_response(client_socket);
    ClientInfo *final_recipients = (ClientInfo *)malloc(sizeof(ClientInfo));
    final_recipients->server_list = (char **)malloc(info->server_count * sizeof(char *));
    final_recipients->key_list = (char ***)malloc(info->server_count * sizeof(char **));
    final_recipients->server_count = 0;

    char *token = strtok(recipients, ",.");
    int input_row = 0; //Track rows in final_recipients
    int input_column = 0;
    while(token){
        for(int i = 0; i < info->server_count; i++){
            int input_column = 0;   //Track columns in key_list for each server
            for(int j = 0; info->key_list[i][j] != NULL; j++){
                if(strcmp(token, info->key_list[i][j]) == 0){
                    //Add the server to final_recipients if it's not added yet
                    if(input_column == 0){
                        //Allocate memory for the key list for this server
                        final_recipients->key_list[input_row] = (char **)malloc((info->server_count + 1) * sizeof(char *));
                        final_recipients->server_list[input_row] = strdup(info->server_list[i]);
                    }
                    //Add the matching key to final_recipients
                    final_recipients->key_list[input_row][input_column++] = strdup(info->key_list[i][j]);
                }
            }
            //If any keys were added for this server, finalize the key_list array for this server
            if(input_column > 0){
                final_recipients->key_list[input_row][input_column] = NULL; // Null-terminate the list
                input_row++; //Move to the next server for future matching
            }
        }
        token = strtok(NULL, ",."); //Get the next recipient token
    }

    final_recipients->server_count = input_row;

    unsigned char fingerprint = create_fingerprint(public_key); //Get fingerprint


    //Determine what message type it is
    if(MessageType == "hello"){ //When it is a hello message, the public key is added to data
        cJSON_AddStringToObject(data_obj, "type", "hello");
        cJSON_AddStringToObject(data_obj, "public_key", public_key);
    }else if(MessageType == "Public"){ //Public Chat
        cJSON_AddStringToObject(data_obj, "type", "public_chat");
        cJSON_AddStringToObject(data_obj, "sender", fingerprint);
        cJSON_AddStringToObject(data_obj, "message", message);
    }else if(MessageType == "Private"){ //Private Chat
        cJSON_AddStringToObject(data_obj, "type", "chat");
        
        cJSON *chat = cJSON_CreateObject();
        
        cJSON *all_participants = cJSON_CreateArray();
        json_object_array_add(all_participants, json_object_new_string(fingerprint));


        for(int i = 0; i < final_recipients->server_count; i++){
            for(int j = 0; info->key_list[i][j] != NULL; j++){
                BIO *bio = BIO_new_mem_buf(info->key_list[i][j], -1);
                EVP_PKEY *Recip_Pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
                json_object_array_add(all_participants, json_object_new_string(create_fingerprint(Recip_Pub_key)));  
            }
        }

        cJSON_AddStringToObject(chat, "message", message);

        unsigned char* key, iv, ciphertext, tag;
        unsigned char *chat_json_str = cJSON_Print(chat); //Convert cJSON to string

        //Encrypt and convert back to cJSON
        AES_Encrypt(chat_json_str, key, iv, ciphertext, tag); 
        chat_json_str = base64_encode(chat_json_str);
        chat = cJSON_Parse(chat_json_str);

        //Adding Symm_keys
        cJSON *symm_keys_array = cJSON_CreateArray();
        for(int i = 0; i < final_recipients->server_count; i++){
            for(int j = 0; info->key_list[i][j] != NULL; j++){    
                BIO *bio = BIO_new_mem_buf(info->key_list[i][j], -1);
                EVP_PKEY *recip_pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
                unsigned char encrypted_key[256]; // Buffer for the RSA-encrypted AES key
                int encrypted_key_len;

                EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(recip_pub_key, NULL);
                if(!ctx || EVP_PKEY_encrypt_init(ctx) <= 0){
                    perror("Could not initiate encryption for AES key");
                }

                if(EVP_PKEY_encrypt(ctx, encrypted_key, &encrypted_key_len, aes_key, sizeof(aes_key)) <= 0){
                    perror("Could not encrypt AES key");
                }

                EVP_PKEY_CTX_free(ctx); // Clean up the context

                char encrypted_key_encoded = base64_encode(encrypted_key);

                json_object_array_add(symm_keys_array, encrypted_key_encoded);
            }
        }

        cJSON *dest_servers = cJSON_CreateArray();
        for(int i = 0; i < final_recipients->server_count; i++){
            json_object_array_add(dest_servers, json_object_new_string(info->server_list[i]));  
        }
        json_object_object_add(data_obj, "destination_servers", dest_servers);

        cJSON_AddStringToObject(data_obj, "iv", base64_encode(iv, 16));

        json_object_object_add(data_obj, "symm_keys", symm_keys_array);

        json_object_object_add(data_obj, "chat", chat);
    }   

    //Turns counter to string
    char counter_str[10];
    snprintf(counter_str, sizeof(counter_str), "%d", counter);

    char *data_json_str = cJSON_Print(data_obj);  //Convert "data" object to JSON string
    size_t data_len = strlen(data_json_str) + strlen(counter_str); 

    char *to_sign = (char *)malloc(data_len + 1);
    snprintf(to_sign, data_len + 1, "%s%s", data_json_str, counter_str); //Concatenate data and counter

    //Sign the data with a private key
    unsigned char *private_key;
    EVP_PKEY_get_raw_private_key(pkeys, private_key, 32);

    unsigned char *signature = sign_data(private_key, to_sign, data_len + 1);
    if (!signature) {
        fprintf(stderr, "Failed to sign data\n");
        return 1;
    }

    //Base64 encode the signature and add to 
    unsigned char encoded_sign = base64_encode(signature, data_len);
    cJSON_AddStringToObject(root, "signature", encoded_sign);

    //Return final JSON
    char *final_json_str = cJSON_Print(root);
    send(client_socket, final_json_str, strlen(final_json_str), flags);

    free(to_sign);
    free(final_json_str);
}

void *receive_messages(void *arg) {
    int socket = *(int *)arg;
    char buffer[BUFFER_SIZE];
    int read_size;

    while ((read_size = recv(socket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
	    // Find the message body location
        char *colon_pos = strrchr(buffer, ':');
        if (colon_pos) {
            char header[BUFFER_SIZE];
            int header_length = colon_pos - buffer + 1;  // include ""
            strncpy(header, buffer, header_length);
            header[header_length] = '\0';

            // Extract and decode the message content
            char *encoded_message = colon_pos + 1;
            while (*encoded_message == ' ') {
                encoded_message++;
            }

            size_t output_length;
            unsigned char *decoded_message = base64_decode(encoded_message, strlen(encoded_message));

            if (decoded_message) {
                decoded_message[output_length] = '\0'; // end correctly 
                printf("%s %s\n", header, decoded_message);
                free(decoded_message);
            }
        } else {
            // When there is no colon, it is a system message.
            printf("system message: %s\n", buffer);
        }
    }

    if (read_size == 0) {
        printf("Server is disconnect\n");
        fflush(stdout);
        return;
    } else if (read_size == -1) {
        perror("Fail to recieve");
        return;
    }

    cJSON *json = cJSON_Parse(buffer);
    if (json) {
        // Extract message type
        cJSON *type = cJSON_GetObjectItem(json, "type");
        if (type && cJSON_IsString(type)) {
            if (strcmp(type->valuestring, "public_chat") == 0) {
                // Handle public chat
                cJSON *sender = cJSON_GetObjectItem(json, "sender");
                cJSON *message = cJSON_GetObjectItem(json, "message");

                if (sender && cJSON_IsString(sender) && message && cJSON_IsString(message)) {
                    printf("[Public Chat] %s: %s\n", sender->valuestring, message->valuestring);
                } else {
                    printf("Invalid public chat message structure.\n");
                }

            } else if (strcmp(type->valuestring, "chat") == 0) {
                // Handle private chat (encrypted)
                cJSON *sender = cJSON_GetObjectItem(json, "sender");
                cJSON *encrypted_message = cJSON_GetObjectItem(json, "chat");

                if (sender && cJSON_IsString(sender) && encrypted_message && cJSON_IsString(encrypted_message)) {
                    printf("[Private Chat] From %s: %s (encrypted message)\n", sender->valuestring, encrypted_message->valuestring);

                    // If needed, decrypt encrypted_message here using AES or RSA
                } else {
                    printf("Invalid private chat message structure.\n");
                }
            } else {
                // Handle other types of messages if needed
                printf("Unknown message type: %s\n", type->valuestring);
            }
        } else {
            printf("Invalid message type or structure.\n");
        }
        cJSON_Delete(json);
    } else {
        printf("Failed to parse JSON.\n");
    }

    return NULL;
}

void send_client_list_request(int client_socket){
    //Create the JSON object for the client list request
    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "type", "client_list_request");

    //Convert JSON object to string
    char *request_str = cJSON_Print(request);

    //Send the request to the server
    send(client_socket, request_str, strlen(request_str), 0);

    //Clean up
    cJSON_Delete(request);
    free(request_str);
}

ClientInfo *receive_client_list_response(int client_socket){
    char buffer[BUFFER_SIZE];
    int read_size;
    //Initialize ClientInfo structure
    ClientInfo *info = (ClientInfo *)malloc(sizeof(ClientInfo));
    info->server_list = NULL;
    info->key_list = NULL;
    info->server_count = 0;

    //Receive the response from the server
    read_size = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if(read_size > 0){
        buffer[read_size] = '\0';  //Null-terminate the data

        //Parse the JSON response
        cJSON *response = cJSON_Parse(buffer);
        if(response == NULL){
            perror("Error parsing JSON response");
            return;
        }

        //Check the type of the response
        cJSON *type = cJSON_GetObjectItem(response, "type");
        if(cJSON_IsString(type) && strcmp(type->valuestring, "client_list") == 0) {
            //Get the list of servers
            cJSON *servers = cJSON_GetObjectItem(response, "servers");
            if(cJSON_IsArray(servers)){
                info->server_count = cJSON_GetArraySize(servers);
                info->server_list = (char **)malloc(info->server_count * sizeof(char *));
                info->key_list = (char ***)malloc(info->server_count * sizeof(char **));

                //Iterate over the servers array
                for(int i = 0; i < info->server_count; i++){
                    cJSON *server = cJSON_GetArrayItem(servers, i);
                    cJSON *address = cJSON_GetObjectItem(server, "address");
                    cJSON *clients = cJSON_GetObjectItem(server, "clients");

                    if(cJSON_IsString(address)){
                        info->server_list[i] = strdup(address->valuestring);
                    }

                    if(cJSON_IsArray(clients)){
                        int client_count = cJSON_GetArraySize(clients);
                        info->key_list[i] = (char **)malloc((client_count + 1) * sizeof(char *));
                        //Iterate over the clients array
                        for(int j = 0; j < client_count; j++){
                            cJSON *client = cJSON_GetArrayItem(clients, j);
                            if(cJSON_IsString(client)){
                                info->key_list[i][j] = strdup(client->valuestring);
                            }
                        }
                        // Null-terminate the client list for this server
                        info->key_list[i][client_count] = NULL;
                    }
                }
            }
        }
        //Clean up
        cJSON_Delete(response);
    } else {
        perror("Failed to receive data from server");
    }

    return info;
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
    send_messages(client_socket, NULL, "hello", NULL, NULL, 0);
    printf("Welcome to the channel, ready to start chatting\n");

    //Create a thread to receive messages
    if (pthread_create(&thread_id, NULL, receive_messages(client_socket), (void *)&client_socket) < 0) {
        perror("Unable to create thread");
        close(client_socket);
        return 1;
    }

    //Send message
    while (1) {
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = 0;

        size_t encoded_length;
        if(message){
            char *messageType; 
            char *recipients; 
            ClientInfo *client_info;

            messageType = strtok(message, " "); //Use strtok to extract the first word 
            if(messageType == "Private"){
                printf("Who would you like to send this message to? please enter the recipent's destination servers separated by commas .");
                fgets(recipients, BUFFER_SIZE, stdin);
                send_client_list_request(client_socket);
                client_info = receive_client_list_response(client_socket);
            }
            send_messages(client_socket, message, messageType, recipients, client_info, 0);
            free(message);
        }
    }
    close(client_socket);
    return 0;
}
