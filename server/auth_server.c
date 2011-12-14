#include "../common/common.c"
#include "auth_server.h"

int pam_authenticate_user(const char *username, const char *password){
    struct auth_struct buffer;
    static struct pam_conv myauthconv = {
	auth_conv,
	NULL
    };
    pam_handle_t *pamh = NULL;
    int ret = 0, authenticated = 0;
    buffer.username = username;
    buffer.password = password;
    myauthconv.appdata_ptr = &buffer;
    
    if (username && password){
	authenticated =
	    (ret = pam_start("login", NULL, &myauthconv, &pamh)) == PAM_SUCCESS &&
	    (ret = pam_authenticate(pamh, 0)) == PAM_SUCCESS &&
	    (ret = pam_acct_mgmt(pamh, 0)) == PAM_SUCCESS;
	
	pam_end(pamh, ret);
    }

    if (authenticated) return 1;
    else return -1;
}

int auth_conv(int num_msg, const struct pam_message **msg, struct pam_response **response, void *appdata_ptr){
    struct pam_response *reply_with = NULL;
    int num_replies;
    struct auth_struct *user_data;
    user_data = (struct auth_struct *)appdata_ptr;
    
    if (num_msg <= 0) return PAM_CONV_ERR;
    
    reply_with = (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
    if (reply_with == NULL) return PAM_SYSTEM_ERR;
    
    for (num_replies = 0; num_replies < num_msg; num_replies++){
	if (msg[num_replies] -> msg_style == PAM_PROMPT_ECHO_OFF){
	    reply_with[num_replies].resp_retcode = PAM_SUCCESS;
	    reply_with[num_replies].resp = strdup(user_data -> password);
	}
	else if (msg[num_replies] -> msg_style == PAM_PROMPT_ECHO_ON){
	    reply_with[num_replies].resp_retcode = PAM_SUCCESS;
	    reply_with[num_replies].resp = strdup(user_data -> username);
	}
	else{
	    free(reply_with);
	    return PAM_CONV_ERR;
	}
    }
    *response = reply_with;
    return PAM_SUCCESS;
}

SSL *get_connection(char *port){
    SSL *my_ssl = NULL;
    static SSL_CTX *my_ssl_ctx = NULL;
    static SSL_METHOD *my_ssl_method = NULL;
    static BIO *server_bio = NULL;
    BIO *client_bio = NULL;
    
    if (port && !server_bio){
	my_ssl_method = TLSv1_server_method();
	if ((my_ssl_ctx = SSL_CTX_new(my_ssl_method)) == NULL){
	    report_error_q("Unable to setup context.", __FILE__, __LINE__, 0);
	}
	SSL_CTX_use_certificate_file(my_ssl_ctx, "server.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(my_ssl_ctx, "server.pem", SSL_FILETYPE_PEM);
	if (!SSL_CTX_check_private_key(my_ssl_ctx)){
	    report_error_q("Private key does not match certificate", __FILE__, __LINE__, 0);
	}
	if ((server_bio = BIO_new_accept(port)) == NULL){
	    report_error_q(ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, 0);
	}
	if (BIO_do_accept(server_bio) <= 0){
	    report_error_q(ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, 0);
	}
    }

    if (port == NULL){
	SSL_CTX_free(my_ssl_ctx);
	BIO_free(server_bio);
    }
    else {
	if (BIO_do_accept(server_bio) <= 0){
	    report_error_q(ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, 0);
	}
	client_bio = BIO_pop(server_bio);
	if ((my_ssl = SSL_new(my_ssl_ctx)) == NULL){
	    report_error_q(ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, 0);
	}
	SSL_set_bio(my_ssl, client_bio, client_bio);
	if (SSL_accept(my_ssl) <= 0){
	    report_error_q(ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, 0);
	}
    }

    return my_ssl;
}

void child_process(SSL *my_ssl){
    char *username = NULL, *password = NULL, *key_file = NULL;
    RSA *users_key = NULL;
    int authenticated = 0;
    int string_size = 0;
    unsigned int signed_size = 0;
    byte_t *signed_buffer = NULL;
    
    w_memory_init();
    
    switch(ssl_read_uint(my_ssl)){
    case SSL_ERROR:
	report_error_q(ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, 0);
	break;
    case REQUEST_KEY_AUTH:
	username = ssl_read_string(my_ssl, 1024);
	string_size = strlen(username) + strlen(network_get_ip_address(my_ssl)) + 10;
	key_file = w_malloc(string_size);
	snprintf(key_file, string_size, "%s.%s.pub", username, network_get_ip_address(my_ssl));
	users_key = key_read_pub(key_file);
	w_free(key_file);
	signed_size = ssl_read_uint(my_ssl);
	signed_buffer = (byte_t *)w_malloc(signed_size);
	if (ssl_read_bytes(my_ssl, signed_buffer, signed_size) != 0){
	    report_error_q("Error reading signed data from client", __FILE__, __LINE__, 0);
	}
	if (key_verify_signature(users_key, signed_buffer, signed_size, username, strlen(username)) == 0){
	    ssl_write_uint(my_ssl, SERVER_AUTH_SUCCESS);
	    printf("(%s) User %s authenticated via PKI.\n", network_get_ip_address(my_ssl), username);
	}
	else {
	    ssl_write_uint(my_ssl, SERVER_AUTH_FAILURE);
	    printf("(%s) User %s failed via PKI.\n", network_get_ip_address(my_ssl), username);
	}
	break;
    case REQUEST_PASS_AUTH:
	username = ssl_read_string(my_ssl, 1024);
	password = ssl_read_string(my_ssl, 1024);
	authenticated = pam_authenticate_user(username, password);
	printf("(%s) User %s %s via PAM.\n", network_get_ip_address(my_ssl), username, authenticated ? "authenticated" : "failed");
	if (authenticated){
	    ssl_write_uint(my_ssl, SERVER_AUTH_SUCCESS);
	    users_key = key_net_read_pub(my_ssl);
	    string_size = strlen(username) + strlen(network_get_ip_address(my_ssl)) + 10;
	    key_file = w_malloc(string_size);
	    snprintf(key_file, string_size, "%s.%s.pub", username, network_get_ip_address(my_ssl));
	    key_write_pub(users_key, key_file);
	    w_free(key_file);
	}
	else ssl_write_uint(my_ssl, SERVER_AUTH_FAILURE);
	break;
    }
    
    if (users_key) key_destroy_key(users_key);
    
    SSL_shutdown(my_ssl);
    SSL_free(my_ssl);
    exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[]){
    char *port = NULL;
    SSL *my_ssl = NULL;
    int my_pid = 0;
    
    if (argc != 2){
	fprintf(stderr, "Usage: %s port.\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    openssl_init();
    port = argv[1];
    
    for (;;){
	my_ssl = get_connection(port);
	my_pid = fork();
	
	if (my_pid == 0){
	    child_process(my_ssl);
	    //daemon(0, 0);
	}
	else wait(my_pid, NULL, 0);
    }
    
    return 0;
}
