#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

SSL *ssl_client_connect(const char *host, const char *port);
const char *getUsername(void);
const char *getUserhome(const char *username);
int haveServerKey(const char *host, const char *username);
RSA *getServerKey(const char *host, const char *username);
void writePrivKey(const char *host, const char *username, RSA *my_key);
const char *getUserPassword(void);

#endif
