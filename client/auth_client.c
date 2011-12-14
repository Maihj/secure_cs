#include "../common/common.c"
#include "auth_client.h"

SSL *ssl_client_connect(const char *host, const char *port){
    SSL_METHOD *my_ssl_method;
    SSL_CTX *my_ssl_ctx;
    SSL *my_ssl;
    BIO *my_bio;
    char *host_port;
    
    host_port = w_malloc(strlen(host) + strlen(port) + 2);
    sprintf(host_port, "%s: %s", port, port);
    my_ssl_method = TLSv1_client_method();
    
    if ((my_ssl_ctx = SSL_CTX_new(my_ssl_method)) == NULL)
	return NULL;
    if ((my_ssl = SSL_new(my_ssl_ctx)) == NULL){
	SSL_CTX_free(my_ssl_ctx);
	return NULL;
    }
    if ((my_bio = BIO_new_connect(host_port)) == NULL){
	SSL_free(my_ssl);
	w_free(host_port);
	return NULL;
    }
    if (BIO_do_connect(my_bio) <= 0){
	SSL_free(my_ssl);
	BIO_free(my_bio);
	w_free(host_port);
	return NULL;
    }
    SSL_set_bio(my_ssl, my_bio, my_bio);
    if (SSL_connect(my_ssl) <= 0){
	SSL_free(my_ssl);
	w_free(host_port);
	return NULL;
    }
    w_free(host_port);
    return my_ssl;
}

const char *getUsername(void){
    static char *username_buffer = NULL;
    uid_t my_uid;
    struct passwd *current_pwent = NULL;
    
    my_uid = getuid();
    current_pwent = getpwent();
    
    if (username_buffer != NULL){
	w_free(username_buffer);
	username_buffer = NULL;
    }
    
    while (current_pwent && !username_buffer){
	if (current_pwent -> pw_uid == my_uid){
	    username_buffer = (char *)w_malloc(strlen(current_pwent -> pw_name) + 1);
	    strncpy(username_buffer, current_pwent -> pw_name, strlen(current_pwent -> pw_name) + 1);
	}
	current_pwent = getpwent();
    }
    endpwent();
    return username_buffer;
}

const char *getUserhome(const char *username){
    static char *home_buffer = NULL;
    struct passwd *current_pwent = NULL;
    
    current_pwent = getpwent();
    if (home_buffer != NULL){
	w_free(home_buffer);
	home_buffer = NULL;
    }

    while (current_pwent){
	if (strcasecmp(username, current_pwent -> pw_name) == 0){
	    home_buffer = (char *)w_malloc(strlen(current_pwent -> pw_dir) + 1);
	    strncpy(home_buffer, current_pwent -> pw_dir, strlen(current_pwent -> pw_dir) + 1);
	}
	current_pwent = getpwent();
    }
    endpwent();
    return home_buffer;
}

int haveServerKey(const char *host, const char *username){
    char *file_path = NULL;
    const char *user_home = NULL;
    FILE *key_file = NULL;
    
    if ((user_home = getUserhome(username)) == NULL)
	report_error_q("Unable to find user's home directory", __FILE__, __LINE__, 0);
    
    file_path = (char *)w_malloc(strlen(host) + strlen(user_home) + 15);
    
    strncpy(file_path, user_home, strlen(user_home));
    strncat(file_path, "/.", 2);
    strncat(file_path, host, strlen(host));
    strncat(file_path, ".priv", strlen(".priv"));
    
    if ((key_file = fopen(file_path, "r")) == NULL){
	w_free(file_path);
	return -1;
    }
    else {
	fclose(key_file);
	w_free(file_path);
	return 0;
    }
}

RSA *getServerKey(const char *host, const char *username){
    char *file_path = NULL;
    const char *user_home = NULL;
    RSA *my_key = NULL;
    
    if ((user_home = getUserhome(username)) == NULL)
	report_error_q("Unable to find user's name directory.", __FILE__, __LINE__, 0);
    
    file_path = (char *)w_malloc(strlen(host) + strlen(user_home) + 15);
    
    strncpy(file_path, user_home, strlen(user_home));
    strncat(file_path, "/.", 2);
    strncat(file_path, host, strlen(host));
    strncat(file_path, ".priv", strlen(".priv"));
    my_key = key_read_priv(file_path);
    w_free(file_path);
    return my_key;
}

void writePrivKey(const char *host, const char *username, RSA *my_key){
    char *file_path = NULL;
    const char *user_home = NULL;
    
    if ((user_home = getUserhome(username)) == NULL)
	report_error_q("Unable to find user's home directory.", __FILE__, __LINE__, 0);
    
    file_path = (char *)w_malloc(strlen(host) + strlen(user_home) + 15);
    
    strncpy(file_path, user_home, strlen(user_home));
    strncat(file_path, "/.", 2);
    strncat(file_path, host, strlen(host));
    strncat(file_path, ".priv", strlen(".priv"));

    if (key_write_priv(my_key, file_path) != 0)
	report_error_q("Unable to write private key to file.", __FILE__, __LINE__, 0);
}

const char *getUserPassword(void){
    struct termios terminal_setup, old_terminal_setup;
    static char *password_buffer[2048];
    char *newline = NULL;
    
    memset(password_buffer, '\0', 2048);
    
    tcgetattr(STDIN_FILENO, &terminal_setup);
    old_terminal_setup = terminal_setup;
    
    terminal_setup.c_lflag &= ~ECHO;
    terminal_setup.c_lflag |= ECHONL;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &terminal_setup);
    
    printf("Password: ");
    fflush(stdout);
    fgets((char *)password_buffer, 2048, stdin);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal_setup);
    
    while ((newline = strstr((char *)password_buffer, "\n")) != NULL){
	*newline = '\0';
    }
    return (char *)password_buffer;
}

int main(int argc, char* argv[]){
    SSL *ssl_connection = NULL;
    const char *host = NULL, *port = NULL;
    const char *username = NULL;
    char *response = NULL;
    char *signed_data_buffer = NULL;
    unsigned int signed_data_buffer_size = 0;
    RSA *my_rsa_key = NULL;
    
    if (argc != 3){
	fprintf(stderr, "Usage: %s host port.\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    w_memory_init();
    openssl_init();
    
    host = argv[1];
    port = argv[2];
    username = getUsername();
    
    if (username == NULL)
	report_error_q("Unable to determine the username of this process.", __FILE__, __LINE__, 0);
 
    if((ssl_connection = ssl_client_connect(host, port)) == NULL)
	report_error_q(ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, 0);
    
    if (haveServerKey(host, username) == 0){
	ssl_write_uint(ssl_connection, REQUEST_KEY_AUTH);
	ssl_write_string(ssl_connection, username);
	my_rsa_key = getServerKey(host, username);
	if (my_rsa_key == NULL)
	    report_error_q("Key file exists, but data is invalid", __FILE__, __LINE__, 0);
    
    
	signed_data_buffer = (char *)w_malloc(key_buffer_size(my_rsa_key));
	signed_data_buffer_size = key_sign_data(my_rsa_key, username, strlen(username), signed_data_buffer, key_buffer_size(my_rsa_key));
	ssl_write_uint(ssl_connection, signed_data_buffer_size);
    
	ssl_write_bytes(ssl_connection, signed_data_buffer, signed_data_buffer_size);
    
	if (ssl_read_uint(ssl_connection) == SERVER_AUTH_SUCCESS){
	    printf("Server responded with SERVER_AUTH_SUCCESS.\n");
	}
	else {
	    printf("Server responded with SERVER_AUTH_SUCCESS.\n");
	}
	w_free(response);
    }
    else {
	ssl_write_uint(ssl_connection, REQUEST_PASS_AUTH);
	ssl_write_string(ssl_connection, username);
	ssl_write_string(ssl_connection, getUserPassword());
	
	if (ssl_read_uint(ssl_connection) == SERVER_AUTH_SUCCESS){
	    printf("Server reponded with SERVER_AUTH_SUCCESS, sending PKI Key.\n");
	    my_rsa_key = key_create_key();
	    if (!my_rsa_key){
		report_error("Error creating RSA key.", __FILE__, __LINE__, 0);
	    }
	    key_net_write_pub(my_rsa_key, ssl_connection);
	    writePrivKey(host, username, my_rsa_key);
	}
	else printf("Server responded with SERVER_AUTH_FAILURE.\n");
    }

    SSL_shutdown(ssl_connection);
    SSL_free(ssl_connection);
    return 0;
}
