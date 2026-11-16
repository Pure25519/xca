/* vi: set sw=4 ts=4:
 *
 * The TLS context of xca-server (BTD-155): TLS 1.2 at least, the server
 * certificate and its key (an encrypted key with tls.key_password), the
 * client CAs and their verification:
 *   auth.api_keys false  SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT:
 *                        no handshake without a certificate of a client CA
 *   auth.api_keys true   SSL_VERIFY_PEER: a certificate is optional, but
 *                        one that is presented must verify
 * A handshake the server refuses (a fatal alert it sends before the
 * handshake is done) is reported to the refusal hook with the peer
 * address, the alert, the verification error and the DNs of a refused
 * certificate, for the audit entry auth.denied.
 *
 * Per connection, the identities that have an auth.login entry are kept
 * with the SSL object (loggedIn()).
 */

#ifndef __XCA_SERVER_TLS_H
#define __XCA_SERVER_TLS_H

#include <functional>
#include <string>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <QString>

class Passwd;

namespace xcaserver {

class Config;

class HandshakeRefusal
{
  public:
	QString peer{};
	QString alert{};
	QString verifyError{};
	QString subject{};
	QString issuer{};
};

/* Sets up ctx for config (keyPassword: the secret of tls.key_password or
 * empty); false with the JSON pointer and the message of the member at
 * fault. Before any connection. */
bool setupTls(SSL_CTX *ctx, const Config &config, const Passwd &keyPassword,
		QString *pointer, QString *message);
/* The function called for a refused handshake, on the connection's
 * thread; set before the server listens, cleared after it stopped */
void setRefusalHook(std::function<void(const HandshakeRefusal &)> hook);

/* Whether the connection has an auth.login entry for actor */
bool loggedIn(const SSL *ssl, const std::string &actor);
void setLoggedIn(const SSL *ssl, const std::string &actor);

/* The address of the peer of the connection */
QString peerAddress(const SSL *ssl);
/* A DN as RFC 4514 string, the form of x509name::rfc4514() */
QString rfc4514(const X509_NAME *name);
/* Lowercase hex SHA-256 of the certificate's DER */
QString certSha256(X509 *cert);

}

#endif
