#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"


// Global variables to be used by both the server and client side of the peer.
Address_t *my_address;

Address_t** network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;

// Helper function to compute a salted SHA256 signature.
void compute_signature(char* password, int password_len, char* salt, hashdata_t hash) {
    int combined_length = password_len + SALT_LEN;
    char* combined_buffer = malloc(combined_length);

    if (combined_buffer == NULL) {
        perror("Failed to allocate memory for combined buffer");
        exit(EXIT_FAILURE);
    }

    memcpy(combined_buffer, password, password_len);
    memcpy(combined_buffer + password_len, salt, SALT_LEN);

    get_data_sha(combined_buffer, hash, combined_length, SHA256_HASH_SIZE);

    free(combined_buffer);
}

// Helper function to compare peer addresses and ports to see if they are the same.
int peer_exists(const Address_t* peer) {
    for (uint32_t i = 0; i < peer_count; i++) {
        if (strncmp(network[i]->ip, peer->ip, IP_LEN) == 0 && network[i]->port == peer->port) {
            return 1;
        }
    }
    return 0;
}

// Build a reply header and send it, followed by the body if there is one.
void send_response(int connfd, uint32_t status, char* body, uint32_t length) {
    ReplyHeader_t reply_header;
    memset(&reply_header, 0, sizeof(ReplyHeader_t));
    reply_header.length = htonl(length);
    reply_header.status = htonl(status);
    reply_header.this_block = htonl(0);
    reply_header.block_count = htonl(1);

    char empty_body[1] = {0};

    get_data_sha(body != NULL ? body : empty_body, reply_header.block_hash, length, SHA256_HASH_SIZE);
    
    memcpy(reply_header.total_hash, reply_header.block_hash, SHA256_HASH_SIZE);

    compsys_helper_writen(connfd, &reply_header, REPLY_HEADER_LEN);
    if (length > 0 && body != NULL) {
        compsys_helper_writen(connfd, body, length);
    }
}
// 11. Send an error response back to the client
void send_error_response(int connfd, uint32_t status, const char *message) {
    fprintf(stderr, "Error: %s\n", message);
    send_response(connfd, status, (char *)message, strlen(message));
}

/*
 * Send a request message to another peer on the network. Unless this is 
 * specifically an 'inform' message as described in the assignment handout, a 
 * reply will always be expected.
 */
void send_message(Address_t peer_address, int command, 
    char* request_body, int body_length)
{
    fprintf(stdout, "Connecting to server at %s:%d to run command %d\n", 
        peer_address.ip, peer_address.port, command);

    compsys_helper_state_t state;
    char msg_buf[MAX_MSG_LEN];

    // Setup connection. Note that we need to convert our port from an integer
    // to a string
    char port_char[6];
    port_char[5] = '\0';
    sprintf(port_char, "%d", peer_address.port);
    int peer_socket = compsys_helper_open_clientfd(peer_address.ip, port_char);
    compsys_helper_readinitb(&state, peer_socket);

    // Construct a request message and send it to the peer
    struct RequestHeader request_header;
    strncpy(request_header.ip, my_address->ip, IP_LEN);
    memcpy(request_header.signature, my_address->signature, SHA256_HASH_SIZE);
    request_header.port = htonl(my_address->port);
    request_header.command = htonl(command);
    request_header.length = htonl(body_length);
    // Copy the header and body together to the message buffer, then write to 
    // the socket
    memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);

    if (body_length > 0) {
        memcpy(msg_buf+REQUEST_HEADER_LEN, request_body, body_length);
    }
    
    compsys_helper_writen(peer_socket, msg_buf, REQUEST_HEADER_LEN+body_length);
    if (command == COMMAND_INFORM) {
        close(peer_socket);
        return;
    }
    

    /*
    3: Handing the response to the register message
    Rather than closing immediately we should probably handle a response.
    */
    // Creating a buffer (of 80 bytes) to read the reply header into.
    char reply_buf[REPLY_HEADER_LEN];

    // Reading the reply header from the peer untill we have read the full 80 bytes.
    uint32_t bytes_read = 0;
    while (bytes_read < REPLY_HEADER_LEN) {
        int n = compsys_helper_readnb(&state, reply_buf + bytes_read, REPLY_HEADER_LEN - bytes_read);

        if (n <= 0) {
            fprintf(stderr, "Error reading response from peer\n");
            close(peer_socket);
            return;
        }
        bytes_read = n + bytes_read;
    }

    // Parsing the reply header from the buffer into a ReplyHeader_t struct.
    ReplyHeader_t reply_header;
    memcpy(&reply_header, reply_buf, REPLY_HEADER_LEN);

    // Converting the length and status fields from network byte order to host byte order.
    uint32_t reply_length = ntohl(reply_header.length);
    uint32_t reply_status = ntohl(reply_header.status);

    printf("Recieved reply from peer: length=%u, status=%u\n", reply_length, reply_status);

    // Checking if the reply body fits in out buffer.
    if (reply_length > MAX_MSG_LEN - REPLY_HEADER_LEN) {
        fprintf(stderr, "Reply body is to large \n");
        close(peer_socket);
        return;
    }

    // Read reply body.
    char reply_body[MAX_MSG_LEN];

    bytes_read = 0;
    while (bytes_read < reply_length) {
        int n = compsys_helper_readnb(&state, reply_body + bytes_read, reply_length - bytes_read);

        if (n <= 0) {
            fprintf(stderr, "Error reading response body from peer\n");
            close(peer_socket);
            return;
        }
        bytes_read = n + bytes_read;
    }

    // Check the status of the reply.
    if (reply_status != STATUS_OK) {
        fprintf(stderr, "Request failed. Server status: %u \n", reply_status);
        close(peer_socket);
        return;
    }

    // Verify the hash of the reply body.
    hashdata_t calculated_hash;
    get_data_sha(reply_body, calculated_hash, reply_length, SHA256_HASH_SIZE);

    if (memcmp(calculated_hash, reply_header.block_hash, SHA256_HASH_SIZE) != 0) {
        fprintf(stderr, "Error: Hash mismatch. \n");
        close(peer_socket);
        return;
    }
    
    // Check the total hash.
    if (memcmp(calculated_hash, reply_header.total_hash, SHA256_HASH_SIZE) != 0) {
        fprintf(stderr, "Error: Total hash mismatch.\n");
        close(peer_socket);
        return;
    }

    // Check if the reply body length is a multiple of the peer address length.
    if (command == COMMAND_REGISTER) {
    if (reply_length % PEER_ADDR_LEN != 0) {
        fprintf(stderr, "Error: Reply body has an invalid peer list length. \n");
        close(peer_socket);
        return;
    }

    uint32_t recieved_peer_count = reply_length / PEER_ADDR_LEN;

    // Read and store the peers from the reply body.
    for (uint32_t i = 0; i < recieved_peer_count; i++) {

        Address_t received_peer;
        memcpy(&received_peer, reply_body + (i * PEER_ADDR_LEN), PEER_ADDR_LEN);
        
        received_peer.port = ntohl(received_peer.port);

        // Make sure the received IP is null-terminated.
        if (memchr(received_peer.ip, '\0', IP_LEN) == NULL) {
            fprintf(stderr, "Error: Received peer has an invalid IP field.\n");
            close(peer_socket);
            return;
        }

        // Check that the received IP and port are valid.
        if (!is_valid_ip(received_peer.ip) || !is_valid_port(received_peer.port)) {
            fprintf(stderr, "Error: Received an invalid peer address.\n");
            close(peer_socket);
            return;
        }

        // Allocate memory for the new peer.
        Address_t *new_peer = malloc(sizeof(Address_t));

        if (new_peer == NULL) {
            perror("malloc");
            close(peer_socket);
            return;
        }

        memcpy(new_peer, &received_peer, sizeof(Address_t));

        pthread_mutex_lock(&network_mutex);

        // Do not add peers that are already in the network.
        if (peer_exists(new_peer)) {
            pthread_mutex_unlock(&network_mutex);
            free(new_peer);
            continue;
        }

        // Expand the network array.
        Address_t **new_network = realloc(network, (peer_count + 1) * sizeof(Address_t *));

        if (new_network == NULL) {
            pthread_mutex_unlock(&network_mutex);
            perror("realloc");
            free(new_peer);
            close(peer_socket);
            return;
        }

        network = new_network;
        network[peer_count] = new_peer;
        peer_count++;

        pthread_mutex_unlock(&network_mutex);

        printf("Added peer: %s:%u\n", new_peer->ip, new_peer->port);

    }
}
    else if (command == COMMAND_RETREIVE) { // Retrieve logic
        FILE *file = fopen(request_body, "wb");
        if (file == NULL) {
            perror("fopen");
            close(peer_socket);
            return;
        }
        // Write the received file data to the file.    
        size_t bytes_written = fwrite(reply_body, 1, reply_length, file);
        
        if (bytes_written != reply_length) {
            fprintf(stderr, "Error writing file.\n");
            fclose(file);
            close(peer_socket);
            return;
        }

    fclose(file);
    }

    close(peer_socket);
}

/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */ 
void* client_thread()
{ // asks for peer IP and port
    char peer_ip[IP_LEN]; 
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%15s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_ip); i<IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%7s", peer_port);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_port); i<PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    Address_t peer_address;
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    /*
    2: Sending a first register message
    Here you should probably send a first register message using the 
    send_message function.
    */
   send_message(peer_address, COMMAND_REGISTER, NULL, 0);

   while (1) {
       char file_path[256];
       fprintf(stdout, "Enter file path to retrieve: ");
        scanf("%255s", file_path);
    // Get a random peer from the network with a mutex lock to ensure thread safety.
    Address_t random_peer;
    pthread_mutex_lock(&network_mutex);
    int random_peer_index = rand() % peer_count;
    random_peer = *network[random_peer_index];
    pthread_mutex_unlock(&network_mutex);
    send_message(random_peer, COMMAND_RETREIVE, file_path, strlen(file_path));
    }
    // You should never see this printed in your finished implementation
    printf("Client thread done\n");

    return NULL;
}


/*
 * Handler for all server requests. This will call the relevent function based 
 * on the parsed command code
 */
void* handle_server_request_thread(void *vargp)
{
    compsys_helper_state_t state;

    int connfd = *((int *)vargp);
    pthread_detach(pthread_self()); 
    free(vargp);

    /*
    5: Reading Server Requests
    Here we should probably actually read in some input data.
    */
    RequestHeader_t header;

    // Initialize the read buffer.
    compsys_helper_readinitb(&state, connfd);

    // Read the request ehader.
    ssize_t bytes_read = compsys_helper_readnb(&state, &header, REQUEST_HEADER_LEN);

    if (bytes_read != REQUEST_HEADER_LEN) {
        fprintf(stderr, "Error reading request header from client\n");
        close(connfd);
        return NULL;
    }

    // Convert values from network byte order.
    header.port = ntohl(header.port);
    header.command = ntohl(header.command);
    header.length = ntohl(header.length);

    // Validate the body length.
    if (header.length > MAX_MSG_LEN - REQUEST_HEADER_LEN) {
          printf("Invalid request body length\n");
          close(connfd);
          return NULL;
        }

    // Read the request body, if there is one.
    char *body = NULL;

    if (header.length > 0) {
        body = malloc(header.length + 1); // +1 for null terminator

        if (body == NULL) {
            perror("malloc");
            close(connfd);
            return NULL;
        }

        bytes_read = compsys_helper_readnb(&state, body, header.length);

        if (bytes_read != header.length) {
            printf("Failed to read request body\n");
            free(body);
            close(connfd);
            return NULL;
        }
        body[header.length] = '\0'; // Null-terminate the body
    }

    // 6: Handling Register Requests
    uint32_t status = STATUS_BAD_REQUEST;
    Address_t new_peer; // Declare a new peer address
    memset(&new_peer, 0, sizeof(Address_t)); // Initialize the new peer address

    // Generate a reply containing the current network.
    uint32_t reply_length = 0;
    char *reply_body = NULL;

    // Check that the request is a register request.
    if (header.command == COMMAND_REGISTER) {
        // A register request should not have a body.
        if (header.length != 0) {
            status = STATUS_MALFORMED;            
        }

        // Validate the IP address and port.
        else if (memchr(header.ip, '\0', IP_LEN) == NULL || 
            !is_valid_ip(header.ip) || 
            header.port > 65535 ||
            !is_valid_port((int)header.port)) {
            
                status = STATUS_MALFORMED;
        }
        else {
            memcpy(new_peer.ip, header.ip, IP_LEN);
            new_peer.port = header.port;

            // Check whether this peer is already registered.
            pthread_mutex_lock(&network_mutex);

            if (peer_exists(&new_peer)) {
                status = STATUS_PEER_EXISTS;
            }
            else {
                // Generate a new random salt.
                generate_random_salt(new_peer.salt);

                // Hash the received signature with the new salt.
                compute_signature((char*)header.signature, SHA256_HASH_SIZE, new_peer.salt, new_peer.signature);

                // Allocate memory for the new peer.
                Address_t *peer_ptr = malloc(sizeof(Address_t));

                if (peer_ptr == NULL) {
                    perror("malloc");
                    status = STATUS_OTHER;
                }
                else {
                    memcpy(peer_ptr, &new_peer, sizeof(Address_t));

                    // Expand the network array.
                    Address_t **new_network = realloc(network, (peer_count + 1) * sizeof(Address_t *));
                    
                    if (new_network == NULL) {
                        perror("realloc");
                        free(peer_ptr);
                        status = STATUS_OTHER;
                    }
                    else {
                        network = new_network;
                        network[peer_count] = peer_ptr;
                        peer_count++;

                        printf("Registered new peer: %s:%u\n", peer_ptr->ip, peer_ptr->port);
                        
                        status = STATUS_OK;
                    }
                }
            }

            pthread_mutex_unlock(&network_mutex);
            
        }
    } else if (header.command == COMMAND_INFORM) { // Handle INFORM requests

    if (header.length != PEER_ADDR_LEN) { // Invalid INFORM request length
        status = STATUS_MALFORMED;
    }
    else { // Valid INFORM request
        Address_t received_peer;
        memcpy(&received_peer, body, PEER_ADDR_LEN);

        // Convert the received port to host byte order.
        received_peer.port = ntohl(received_peer.port);

        // Validate the received peer.
        if (memchr(received_peer.ip, '\0', IP_LEN) == NULL ||
            !is_valid_ip(received_peer.ip) ||
            !is_valid_port(received_peer.port)) {
            status = STATUS_MALFORMED;
        }
        else { // Valid INFORM request
            Address_t *peer_ptr = malloc(sizeof(Address_t));

            if (peer_ptr == NULL) {
                status = STATUS_OTHER;
            }
            else { // Allocate memory for the new peer and copy the received peer data
                memcpy(peer_ptr, &received_peer, sizeof(Address_t));

                pthread_mutex_lock(&network_mutex);

                if (peer_exists(peer_ptr)) {
                    free(peer_ptr);
                    status = STATUS_OK;
                }
                else {
                    Address_t **new_network = realloc(
                        network, (peer_count + 1) * sizeof(Address_t *)
                    );

                    if (new_network == NULL) {
                        free(peer_ptr);
                        status = STATUS_OTHER;
                    }
                    else {
                        network = new_network;
                        network[peer_count] = peer_ptr;
                        peer_count++;
                        status = STATUS_OK;

                        printf("Added peer through INFORM: %s:%u\n",
                            peer_ptr->ip, peer_ptr->port);
                    }
                }

                pthread_mutex_unlock(&network_mutex);
            }
        }
    }
} else if (header.command == COMMAND_RETREIVE) {
    if (header.length == 0) {
        status = STATUS_MALFORMED;
    }
    else {
        FILE *file = fopen(body, "rb");

        if (file == NULL) {
            status = STATUS_OTHER;
        }
        else { // Valid RETRIEVE request
            fseek(file, 0, SEEK_END);
            long file_size = ftell(file);
            rewind(file);

            reply_body = malloc(file_size);

            if (reply_body == NULL) {
                fclose(file);
                status = STATUS_OTHER;
            }
            else { // Valid RETRIEVE request
                size_t bytes_read = fread(reply_body, 1, file_size, file);

                if (bytes_read != file_size) {
                    free(reply_body);
                    reply_body = NULL;
                    status = STATUS_OTHER;
                }
                else {
                    reply_length = file_size;
                    status = STATUS_OK;
                }
            }

            fclose(file);
        }
    }
}


// 8. Inform all existing peers about the new peer
    if (header.command == COMMAND_REGISTER && status == STATUS_OK) { // Handle new peer registration
    pthread_mutex_lock(&network_mutex);

    Address_t *peers_to_inform = malloc(peer_count * sizeof(Address_t));
    uint32_t inform_count = 0;

    if (peers_to_inform != NULL) { // Check if memory allocation was successful
        for (uint32_t i = 0; i < peer_count; i++) {

            // Skip ourselves
            if (strcmp(network[i]->ip, my_address->ip) == 0 &&
                network[i]->port == my_address->port) {
                continue;
            }

            // Skip the newly registered peer
            if (strcmp(network[i]->ip, new_peer.ip) == 0 &&
                network[i]->port == new_peer.port) {
                continue;
            }

            // Skip peers without a signature or salt
            hashdata_t empty_signature = {0};
            char empty_salt[SALT_LEN] = {0};

            if (memcmp(network[i]->signature, empty_signature,
                       sizeof(empty_signature)) == 0 ||
                memcmp(network[i]->salt, empty_salt, SALT_LEN) == 0) {
                continue;
            }

            peers_to_inform[inform_count] = *network[i]; // Copy peer information
            inform_count++;
        }
    }

    pthread_mutex_unlock(&network_mutex); 

    if (peers_to_inform != NULL) { // Check if memory allocation was successful
        // Convert the new peer's port to network byte order
        Address_t inform_peer = new_peer;
        inform_peer.port = htonl(inform_peer.port);

        // Send INFORM to all existing peers
        for (uint32_t i = 0; i < inform_count; i++) {
            send_message(peers_to_inform[i], COMMAND_INFORM,
                         (char *)&inform_peer, PEER_ADDR_LEN);
        }

        free(peers_to_inform);
    }
}

    if (status == STATUS_OK && header.command == COMMAND_REGISTER) { // Handle new peer registration
        pthread_mutex_lock(&network_mutex);

        reply_length = peer_count * PEER_ADDR_LEN;

        // Make sure the reply fits within the message buffer.
        if (reply_length > MAX_MSG_LEN - REPLY_HEADER_LEN) {
            reply_length = 0;
            status = STATUS_OTHER;
        }
        else {
            reply_body = malloc(reply_length);

            if (reply_body == NULL) {
                perror("malloc");
                reply_length = 0;
                status = STATUS_OTHER;
            }
            else {
                for (uint32_t i = 0; i < peer_count; i++) {
                    Address_t entry;
                    memcpy(&entry, network[i], sizeof(Address_t));
                    entry.port = htonl(entry.port);
                    memcpy(reply_body + (i * PEER_ADDR_LEN), &entry, PEER_ADDR_LEN);
                }
            }
        }

        pthread_mutex_unlock(&network_mutex);
    }

    if (header.command != COMMAND_INFORM) { // Not an INFORM request
    if (status != STATUS_OK) {
        const char *error_message;

        switch (status) { // Handle different error statuses
            case STATUS_BAD_REQUEST:
                error_message = "Bad request";
                break;
            case STATUS_MALFORMED:
                error_message = "Malformed request";
                break;
            case STATUS_PEER_EXISTS:
                error_message = "Peer already exists";
                break;
            case STATUS_OTHER:
                error_message = "Internal server error";
                break;
            default:
                error_message = "Unknown error";
                break;
        }

        send_error_response(connfd, status, error_message);
    }
    else {
        send_response(connfd, status, reply_body, reply_length);
    }
}

    free(reply_body);
    free(body);
    close(connfd);
    return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread()
{
    int listenfd;
    
    // Start listening
    char port_char[6];
    port_char[5] = '\0';
    sprintf(port_char, "%d", my_address->port);
    listenfd = compsys_helper_open_listenfd(port_char);
    if (listenfd < 0) {
        perror("open_listenfd");
        return NULL;
}
    
    printf("Starting to listen on %s:%d\n", my_address->ip, my_address->port);
    
    /*
    4: Setting Up Server Threading
    Here we should implement some sort of loop to accept inbound communications
    and handle them within a thread so they do not block subsequent 
    connections. The function 'handle_server_request_thread' has been provided
    as a simple skeleton function you could use to process your requests in.
    */
   
    while(1) {
        struct sockaddr_in client_address;
        socklen_t client_address_length = sizeof(client_address);
        
        // Wait for an incoming connection.
        int connfd = accept(listenfd,
            (struct sockaddr *)&client_address,
            &client_address_length);

        if (connfd < 0)
        {
            perror("accept");
            continue;
        }

        // Allocate memory for the connection descriptor.
        int *connfd_ptr = malloc(sizeof(int));

        if (connfd_ptr == NULL)
        {
            perror("malloc");
            close(connfd);
            continue;
        }

        *connfd_ptr = connfd;

        // Create a new thread to handle the request.
        pthread_t request_thread;

        if (pthread_create(&request_thread, NULL,
            handle_server_request_thread, connfd_ptr) != 0)
        {
            perror("pthread_create");
            free(connfd_ptr);
            close(connfd);
            continue;
        }
    }

    // You should never see this printed in your finished implementation
    printf("Server thread done\n");

    return NULL;
}


int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (Address_t*)malloc(sizeof(Address_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", 
            my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Most correctly, we should randomly generate our salts, but this can make
    // repeated testing difficult so feel free to use the hard coded salt below
    char user_salt[SALT_LEN+1] = "0123456789ABCDEF";
    //generate_random_salt(user_salt);
    memcpy(my_address->salt, user_salt, SALT_LEN);

    /* 
    1: Setting Up
    After determining our salt but before saving our address we should probably
    work out what our signature should be. 
    */
   compute_signature(password, strlen(password), user_salt, my_address->signature);

    // Start our record of the network by recording our own address. Make sure
    // any time we update this array we also update the peer_count.
    network = malloc(sizeof(Address_t*));
    network[0] = my_address;
    peer_count = 1;

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete. 
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}