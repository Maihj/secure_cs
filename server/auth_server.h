#ifndef AUTH_SERVER_H
#define AUTH_SERVER_H

#include <security/pam_appl.h>

SSL *get_connection(char *port);
int pam_authenticate_user(const char *, const char *);
int auth_conv(int, const struct pam_message **, struct pam_response **, void *);
void child_process(SSL *my_ssl);
int auth_conv(int num_msg, const struct pam_message **msg, struct pam_response **response, void *appdata_ptr);

typedef struct auth_struct{
    const char *username;
    const char *password;
}auth_struct;

#endif
