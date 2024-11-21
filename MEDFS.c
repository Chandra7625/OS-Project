#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_REQUESTS 5

// Global variables for request logging
char request_log[MAX_REQUESTS][BUFFER_SIZE];
int request_count = 0;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// SSL context (shared among threads)
SSL_CTX *ssl_ctx = NULL;

// Function to log requests
void log_request(const char *request) {
    pthread_mutex_lock(&log_mutex);

    if (request_count < MAX_REQUESTS) {
        snprintf(request_log[request_count], sizeof(request_log[request_count]), "%s", request);
        request_count++;
    } else {
        for (int i = 1; i < MAX_REQUESTS; i++) {
            snprintf(request_log[i - 1], sizeof(request_log[i - 1]), "%s", request_log[i]);
        }
        snprintf(request_log[MAX_REQUESTS - 1], sizeof(request_log[MAX_REQUESTS - 1]), "%s", request);
    }

    pthread_mutex_unlock(&log_mutex);
}

// Function to handle incoming requests
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Receive the request from the client
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    buffer[bytes_received] = '\0';

    // Log the request
    log_request(buffer);

    // Send a response back to the client
    char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Request Log</h1><ul>";
    SSL_write(ssl, response, strlen(response));

    pthread_mutex_lock(&log_mutex);
    for (int i = 0; i < request_count; i++) {
        char log_entry[BUFFER_SIZE];
        int len = snprintf(log_entry, sizeof(log_entry), "<li>%s</li>", request_log[i]);
        if (len >= sizeof(log_entry)) {
            log_entry[sizeof(log_entry) - 4] = '\0';
            strcat(log_entry, "...</li>");
        }
        SSL_write(ssl, log_entry, strlen(log_entry));
    }
    pthread_mutex_unlock(&log_mutex);

    char *end_response = "</ul></body></html>";
    SSL_write(ssl, end_response, strlen(end_response));

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

// Function to start the server and listen for incoming connections
void *server_thread(void *arg) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) < 0) {
        perror("listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server successfully bound to port %d\n", PORT);
    printf("Server is listening for encrypted connections...\n");

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }

        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        pthread_t thread;
        pthread_create(&thread, NULL, (void *(*)(void *))handle_request, (void *)ssl);
        pthread_detach(thread);
    }

    close(server_socket);
    return NULL;
}

// Initialize OpenSSL
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Create SSL context
SSL_CTX *create_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Configure SSL context with certificate and key
void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main() {
    initialize_openssl();

    ssl_ctx = create_context();
    configure_context(ssl_ctx);

    pthread_t server_thread_id;
    pthread_create(&server_thread_id, NULL, server_thread, NULL);
    pthread_join(server_thread_id, NULL);

    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();

    return 0;
}
