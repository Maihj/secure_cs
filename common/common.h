#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <termios.h>
#include <unistd.h>
#include <pwd.h>

#define ENTROPY_SIZE 512
#define byte_t char
#define REQUEST_KEY_AUTH    10
#define REQUEST_PASS_AUTH   11
#define SERVER_AUTH_SUCCESS 1
#define SERVER_AUTH_FAILURE 2
#define SSL_ERROR           0

void report_error_q(const char* msg, const char* file, int line_no, int use_perror);
void report_error(const char* msg, const char* file, int line_no, int use_perror);

typedef struct memory_list{
    void* address;
    size_t size;
    struct memory_list *next;
    struct memory_list *prev;
}memory_list;

void *w_malloc(size_t bytes);
void w_free(void* f_address);
void w_free_all(void);
void w_memory_init(void);
memory_list *memory_list_head;
unsigned long global_memory_count;

void openssl_init(void);
void openssl_destroy(void);

char *ssl_read_string(SSL *my_ssl, size_t limit);
void ssl_write_string(SSL *my_ssl, const char* message);
unsigned int ssl_read_uint(SSL *my_ssl);
void ssl_write_uint(SSL *my_ssl, unsigned int value);
byte_t ssl_read_byte(SSL *my_ssl);
int ssl_read_bytes(SSL *my_ssl, void* buf, unsigned int limit);
void ssl_write_byte(SSL *my_ssl, byte_t this_byte);
void ssl_write_bytes(SSL *my_ssl, void* message, unsigned int length);

const char *network_get_ip_address(SSL *my_ssl);

RSA * key_create_key(void);
void key_destroy_key(RSA *);
unsigned int key_buffer_size(RSA *);
unsigned int key_sign_data(RSA *, const char *, unsigned int, char *, unsigned int);
int key_write_priv(RSA *, char *);
RSA *key_read_priv(char *);
void key_net_write_pub(RSA *, SSL *);
RSA *key_net_read_pub(SSL *);
int key_verify_signature(RSA *, char *, unsigned int, char *, unsigned int);
int key_write_pub(RSA *, char *);
RSA *key_read_pub(char *);

#endif
