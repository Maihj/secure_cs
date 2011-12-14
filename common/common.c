#include "common.h"

void report_error(const char* msg, const char* file, int line_no, int use_perror){
    fprintf(stderr, "[%s: %d]", file, line_no);
    if (use_perror != 0) perror(msg);
    else fprintf(stderr, "%s\n", msg);
}

void report_error_q(const char* msg, const char* file, int line_no, int use_perror){
    report_error(msg, file, line_no, use_perror);
    exit(EXIT_FAILURE);
}

void *w_malloc(size_t bytes){
    void* memory = NULL;
    memory_list *new_item = NULL;
    memory = calloc(bytes, 1);
    new_item = calloc(1, sizeof(struct memory_list));
    if (memory){
	if (new_item == NULL){
	    report_error_q("Memory allocation error, no room for memory list item.", __FILE__, __LINE__, 0);
	}
	global_memory_count += bytes + sizeof(struct memory_list);
	new_item -> address = memory;
	new_item -> size = bytes;
	new_item -> next = NULL;
	new_item -> prev = NULL;
	if (memory_list_head){
	    new_item -> next = memory_list_head;
	    memory_list_head -> prev = new_item;
	    memory_list_head = new_item;
	}
	else memory_list_head = new_item;
	return memory;
    }
    else{
	report_error_q("Memory allocation error, out of memory.", __FILE__, __LINE__, 0);
	return NULL;
    }
}

void w_free(void* f_address){
    memory_list *temp = NULL, *found = NULL;
    if (f_address == NULL) return;
    for (temp = memory_list_head; temp != NULL; temp = temp -> next){
	if (temp -> address == f_address){
	    found = temp;
	    break;
	}
    }
    
    if (!found){
	report_error_q("Unable to free memory not previously allocated.", __FILE__, __LINE__, 0);
    }

    global_memory_count -= found -> size + sizeof(struct memory_list);

    free(f_address);
    
    if (found -> prev) found -> prev -> next = found -> next;
    if (found -> next) found -> next -> prev = found -> prev;
    if (found == memory_list_head) memory_list_head = found -> next;
    
    free(found);
}

void w_free_all(void){
    memory_list *temp = NULL;
    
    while (memory_list_head){
	free(memory_list_head -> address);
	temp = memory_list_head -> next;
	free(memory_list_head);
	memory_list_head = temp;
    }
}

void w_memory_init(void){
    static int state = 0;
    if (state != 0) return;
    
    state = 1;
    memory_list_head = NULL;
    global_memory_count = 0;
    atexit(w_free_all);
}

void openssl_init(void){
    static int state = 0;
    int bytes_read = 0;
    
    if (state != 0) return;
    
    state = 1;
    atexit(openssl_destroy);
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    printf("Seeding PRNG with /dev/random, this may take a momment... ");
    fflush(stdout);
    if ((bytes_read = RAND_load_file("/dev/random", ENTROPY_SIZE)) != ENTROPY_SIZE)
	report_error_q("Seeding PRNG failed", __FILE__, __LINE__, 0);
    printf("Done.\n");
    fflush(stdout);
}

void openssl_destroy(void){
    EVP_cleanup();
    ERR_free_strings();
}

char *ssl_read_string(SSL *my_ssl, size_t limit){
    char* buffer = NULL;
    char this_one;
    int error = 0, read_in = 0;
    
    buffer = w_malloc(limit);
    
    while (read_in < limit){
	error = SSL_read(my_ssl, &this_one, 1);
	if (error > 0){
	    buffer[read_in++] = this_one;
	    if (this_one == '\0') return buffer;
	}
	else return buffer;
    }
    buffer[limit-1] = '\0';
    return buffer;
}

void ssl_write_string(SSL *my_ssl, const char* message){
    int ret_val = 0, bytes_written = 0;
    int bytes_to_write;
    
    bytes_to_write = strlen(message) + 1;
    
    while (bytes_written < bytes_to_write){
	ret_val = SSL_write(my_ssl, message + bytes_written,bytes_to_write - bytes_written);
	if (ret_val <= 0) break;
	else bytes_written += ret_val;
    }
}

unsigned int ssl_read_uint(SSL *my_ssl){
    unsigned int value = 0;
    
    if (ssl_read_bytes(my_ssl, &value, sizeof(unsigned int)) != -1){
	value = ntohl(value);
	return value;
    }
    else return 0;
}

void ssl_write_uint(SSL *my_ssl, unsigned int value){
    unsigned int to_write = 0;
    to_write = htonl(value);
    ssl_write_bytes(my_ssl, &to_write, sizeof(unsigned int));
}

byte_t ssl_read_byte(SSL *my_ssl){
    byte_t this_byte;
    if (SSL_read(my_ssl, &this_byte, sizeof(byte_t)) != 1) return '\0';
    else return this_byte;
}

int ssl_read_bytes(SSL *my_ssl, void* buf, unsigned int limit){
    byte_t *my_buf = NULL;
    unsigned int x = 0;
    
    my_buf = (byte_t *)buf;
    
    for(; x < limit; x++){
	my_buf[x] = ssl_read_byte(my_ssl);
    }
    return 0;
}

void ssl_write_byte(SSL *my_ssl, byte_t this_byte){
    SSL_write(my_ssl, &this_byte, 1);
}

void ssl_write_bytes(SSL *my_ssl, void* message, unsigned int length){
    int ret_val = 0, bytes_written = 0;
    byte_t *buffer = NULL;
    
    buffer = (byte_t *)message;
    
    while (bytes_written < length){
	ret_val = SSL_write(my_ssl, buffer + bytes_written, length - bytes_written);
	
	if (ret_val <= 0) break;
	else bytes_written += ret_val;
    }
}

const char *network_get_ip_address(SSL *my_ssl){
    struct sockaddr_in addr;
    int sizeof_addr = 0;
    int clientFd = 0;
    clientFd = SSL_get_fd(my_ssl);
    sizeof_addr = sizeof(addr);
    getpeername(clientFd, (struct sockaddr *)&addr, &sizeof_addr);
    return(const char *) inet_ntoa(addr.sin_addr);
}

RSA * key_create_key(void){
    RSA *new_key = NULL;
    
    new_key = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    
    if (new_key){
	if (RSA_check_key(new_key) == 1) return new_key;
	else return NULL;
    }
    return NULL;
}

void key_destroy_key(RSA *this_key){
    if (this_key) RSA_free(this_key);
}

unsigned int key_buffer_size(RSA *this_key){
    return RSA_size(this_key);
}

unsigned int key_sign_data(RSA *this_key, const char *original, unsigned int orig_size, char *signd, unsigned int signd_length){
    EVP_MD_CTX my_evp;
    EVP_PKEY *pkey;
    unsigned int signed_length = 0;
    
    if (this_key == NULL) return 0;
    
    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, this_key);
    signed_length = signd_length;
    
    EVP_SignInit(&my_evp, EVP_md5());
    EVP_SignUpdate(&my_evp, original, orig_size);
    EVP_SignFinal(&my_evp, signd, &signed_length, pkey);
    EVP_PKEY_free(pkey);
    return signed_length;
}

int key_write_priv(RSA *this_key, char *filename){
    FILE *store_file = NULL;
    int retval = 0;
    
    store_file = fopen(filename, "w");
    
    if (!store_file) return -1;
    
    retval = PEM_write_RSAPrivateKey(store_file, this_key, NULL, NULL, 0, NULL, NULL);
    
    fclose(store_file);
    
    if (retval) return 0;
    else return -1;
}

RSA *key_read_priv(char *filename){
    FILE *store_file = NULL;
    RSA *this_key = NULL;
    store_file = fopen(filename, "r");
    
    if (!store_file) return NULL;
    
    this_key = PEM_read_RSAPrivateKey(store_file, NULL, NULL, NULL);
    
    fclose(store_file);
    return this_key;
}

void key_net_write_pub(RSA *this_key, SSL *my_ssl){
    unsigned int buf_size;
    unsigned char *buf, *next;
    
    buf_size = i2d_RSAPublicKey(this_key, NULL);
    ssl_write_uint(my_ssl, buf_size);
    buf = next = (unsigned char *)w_malloc(buf_size);
    i2d_RSAPublicKey(this_key, &next);
    ssl_write_bytes(my_ssl, buf, buf_size);
    w_free(buf);
}

RSA *key_net_read_pub(SSL *my_ssl){
    RSA *this_key = NULL;
    unsigned int len = 0;
    unsigned char *temp = NULL, *buff;
    
    len = ssl_read_uint(my_ssl);
    buff = temp = (unsigned char *)w_malloc(len);
    ssl_read_bytes(my_ssl, temp, len);
    this_key = d2i_RSAPublicKey(NULL, &temp, len);
    w_free(buff);
    return this_key;
}

int key_verify_signature(RSA *this_key, char *signd, unsigned int s_length, char *u_signed, unsigned int u_length){
    EVP_MD_CTX my_evp;
    EVP_PKEY *pkey;
    int retval = 0;
    
    if (this_key == NULL) return -1;
    
    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, this_key);
    EVP_VerifyInit(&my_evp, EVP_md5());
    EVP_VerifyUpdate(&my_evp, u_signed, u_length);
    retval = EVP_VerifyFinal(&my_evp, signd, s_length, pkey);
    EVP_PKEY_free(pkey);
    
    if (retval) return 0;
    else return -1;
}

int key_write_pub(RSA *this_key, char *filename){
    FILE *store_file = NULL;
    int retval = 0;
    
    store_file = fopen(filename, "w");
    
    if (!store_file) return -1;
    
    retval = PEM_write_RSA_PUBKEY(store_file, this_key);
    fclose(store_file);
    
    if (retval) return 0;
    else return -1;
}

RSA *key_read_pub(char *filename){
    FILE *store_file = NULL;
    RSA *this_key = NULL;
    
    store_file = fopen(filename, "r");
    if (!store_file) return NULL;
    
    this_key = PEM_read_RSA_PUBKEY(store_file, NULL, NULL, NULL);
    fclose(store_file);
    
    return this_key;
}
