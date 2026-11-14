/* vi: set sw=4 ts=4:
 *
 * The TLS context of xca-server (BTD-155), see tls.h.
 */

#include "tls.h"

#include <cstdio>
#include <cstring>
#include <set>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <QObject>

#include "lib/Passwd.h"

#include "config.h"

namespace xcaserver {

namespace {

/* What the server keeps per connection, with the SSL object */
class ConnState
{
  public:
	std::set<std::string> logged{};
	QString verifyError{};
	QString subject{};
	QString issuer{};
	bool refused{};
};

int connIndex = -1;
std::function<void(const HandshakeRefusal &)> refusalHook;

void freeConnState(void *, void *ptr, CRYPTO_EX_DATA *, int, long, void *)
{
	delete static_cast<ConnState *>(ptr);
}

/* Only the connection's thread uses its state */
ConnState *state(const SSL *ssl)
{
	if (connIndex < 0)
		return nullptr;
	auto *st = static_cast<ConnState *>(SSL_get_ex_data(ssl, connIndex));
	if (!st) {
		st = new ConnState();
		if (!SSL_set_ex_data(const_cast<SSL *>(ssl), connIndex, st)) {
			delete st;
			return nullptr;
		}
	}
	return st;
}

int passwordCallback(char *buf, int size, int, void *userdata)
{
	const Passwd *pw = static_cast<const Passwd *>(userdata);
	if (!pw || pw->isEmpty() || pw->size() > size)
		return 0;
	std::memcpy(buf, pw->constData(), size_t(pw->size()));
	return int(pw->size());
}

/* Keeps why a client certificate was refused, for the alert */
int verifyCallback(int ok, X509_STORE_CTX *x)
{
	if (ok)
		return ok;
	SSL *ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(x,
				SSL_get_ex_data_X509_STORE_CTX_idx()));
	ConnState *st = ssl ? state(ssl) : nullptr;
	if (st && st->verifyError.isEmpty()) {
		st->verifyError = QString::fromUtf8(
			X509_verify_cert_error_string(
				X509_STORE_CTX_get_error(x)));
		X509 *leaf = X509_STORE_CTX_get0_cert(x);
		if (leaf) {
			st->subject = rfc4514(X509_get_subject_name(leaf));
			st->issuer = rfc4514(X509_get_issuer_name(leaf));
		}
	}
	return ok;
}

/* A fatal alert the server sends during the handshake: refused */
void infoCallback(const SSL *ssl, int where, int ret)
{
	if (!(where & SSL_CB_WRITE_ALERT) || SSL_is_init_finished(ssl))
		return;
	if (std::strcmp(SSL_alert_type_string(ret), "F") != 0)
		return;
	ConnState *st = state(ssl);
	if (!st || st->refused)
		return;
	st->refused = true;
	HandshakeRefusal r;
	r.peer = peerAddress(ssl);
	r.alert = QString::fromUtf8(SSL_alert_desc_string_long(ret));
	r.verifyError = st->verifyError;
	r.subject = st->subject;
	r.issuer = st->issuer;
	if (refusalHook)
		refusalHook(r);
}

bool failed(QString *pointer, QString *message, const QString &p,
		const QString &m)
{
	*pointer = p;
	*message = m;
	ERR_clear_error();
	return false;
}

}

bool setupTls(SSL_CTX *ctx, const Config &config, const Passwd &keyPassword,
		QString *pointer, QString *message)
{
	if (connIndex < 0)
		connIndex = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr,
						freeConnState);
	if (connIndex < 0)
		return failed(pointer, message, "/tls", QObject::tr(
			"no index for the connection state"));
	/* explicit, whatever the library's default is */
	if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
		return failed(pointer, message, "/tls", QObject::tr(
			"TLS 1.2 cannot be set as the minimum version"));
	/* never a prompt: no password, no key */
	SSL_CTX_set_default_passwd_cb(ctx, passwordCallback);
	SSL_CTX_set_default_passwd_cb_userdata(ctx,
			const_cast<Passwd *>(&keyPassword));
	QByteArray cert = config.tlsCert.toLocal8Bit();
	QByteArray key = config.tlsKey.toLocal8Bit();
	QByteArray clientCa = config.tlsClientCa.toLocal8Bit();
	bool certOk = SSL_CTX_use_certificate_chain_file(ctx,
				cert.constData()) == 1;
	bool keyOk = certOk && SSL_CTX_use_PrivateKey_file(ctx,
				key.constData(), SSL_FILETYPE_PEM) == 1;
	SSL_CTX_set_default_passwd_cb_userdata(ctx, nullptr);
	if (!certOk)
		return failed(pointer, message, "/tls/cert", QObject::tr(
			"the certificate '%1' cannot be loaded")
			.arg(config.tlsCert));
	if (!keyOk && !keyPassword.isEmpty())
		return failed(pointer, message, "/tls/key_password",
			QObject::tr("the key '%1' cannot be loaded with "
			"this password").arg(config.tlsKey));
	if (!keyOk)
		return failed(pointer, message, "/tls/key", QObject::tr(
			"the key '%1' cannot be loaded (an encrypted key "
			"needs /tls/key_password)").arg(config.tlsKey));
	if (SSL_CTX_check_private_key(ctx) != 1)
		return failed(pointer, message, "/tls/key", QObject::tr(
			"the key '%1' does not belong to the certificate '%2'")
			.arg(config.tlsKey, config.tlsCert));
	if (SSL_CTX_load_verify_locations(ctx, clientCa.constData(),
				nullptr) != 1)
		return failed(pointer, message, "/tls/client_ca", QObject::tr(
			"the client CAs '%1' cannot be loaded")
			.arg(config.tlsClientCa));
	STACK_OF(X509_NAME) *names = SSL_load_client_CA_file(
					clientCa.constData());
	if (!names)
		return failed(pointer, message, "/tls/client_ca", QObject::tr(
			"no CA names in '%1'").arg(config.tlsClientCa));
	SSL_CTX_set_client_CA_list(ctx, names);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | (config.apiKeys ? 0 :
				SSL_VERIFY_FAIL_IF_NO_PEER_CERT),
				verifyCallback);
	SSL_CTX_set_info_callback(ctx, infoCallback);
	ERR_clear_error();
	return true;
}

void setRefusalHook(std::function<void(const HandshakeRefusal &)> hook)
{
	refusalHook = std::move(hook);
}

bool loggedIn(const SSL *ssl, const std::string &actor)
{
	ConnState *st = state(ssl);
	return st && st->logged.count(actor);
}

void setLoggedIn(const SSL *ssl, const std::string &actor)
{
	ConnState *st = state(ssl);
	if (st)
		st->logged.insert(actor);
}

QString peerAddress(const SSL *ssl)
{
	sockaddr_storage addr{};
	socklen_t len = sizeof addr;
	int fd = SSL_get_fd(ssl);
	if (fd < 0 || getpeername(fd, reinterpret_cast<sockaddr *>(&addr),
				&len) != 0)
		return QString();
	char host[INET6_ADDRSTRLEN] = "";
	if (addr.ss_family == AF_INET)
		inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(&addr)
				->sin_addr, host, sizeof host);
	else if (addr.ss_family == AF_INET6)
		inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(&addr)
				->sin6_addr, host, sizeof host);
	return QString::fromLatin1(host);
}

QString rfc4514(const X509_NAME *name)
{
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio)
		return QString();
	/* RFC 2253 escaping without ESC_MSB, as x509name::rfc4514() */
	X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253 &
				~ASN1_STRFLGS_ESC_MSB);
	char *data = nullptr;
	long len = BIO_get_mem_data(bio, &data);
	QString s = QString::fromUtf8(data, int(len));
	BIO_free(bio);
	return s;
}

QString certSha256(X509 *cert)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	if (!cert || !X509_digest(cert, EVP_sha256(), md, &len))
		return QString();
	return QString::fromLatin1(QByteArray(reinterpret_cast<char *>(md),
				int(len)).toHex());
}

}
