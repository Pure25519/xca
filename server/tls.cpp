/* vi: set sw=4 ts=4:
 *
 * The TLS context of xca-server (BTD-155), see tls.h.
 */

#include "tls.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <set>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

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
	int verifyCode{};
	QString subject{};
	QString issuer{};
	bool refused{};
};

int connIndex = -1;
std::function<void(const HandshakeRefusal &)> refusalHook;

/* The CRL snapshot of the handshakes (BTD-313) */
std::mutex crlMutex;
std::shared_ptr<const ClientCrls> crlSnapshot;

/* The short reason of a revocation error for auth.denied, else empty */
QString revocationReason(int code)
{
	switch (code) {
	case X509_V_ERR_CERT_REVOKED:
		return "revoked";
	case X509_V_ERR_UNABLE_TO_GET_CRL:
	case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
		return "crl_missing";
	case X509_V_ERR_CRL_HAS_EXPIRED:
		return "crl_expired";
	case X509_V_ERR_CRL_NOT_YET_VALID:
		return "crl_not_yet_valid";
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
	case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
	case X509_V_ERR_DIFFERENT_CRL_SCOPE:
	case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
		return "crl_invalid";
	}
	return QString();
}

/* The chain verification of a client certificate: OpenSSL's, with the
 * CRLs of the current snapshot and the leaf's CRL check (BTD-313). The
 * snapshot stays alive until the verification is done. */
int verifyWithCrls(X509_STORE_CTX *x, void *)
{
	std::shared_ptr<const ClientCrls> snap = clientCrls();
	STACK_OF(X509_CRL) *none = nullptr;
	STACK_OF(X509_CRL) *crls = snap ? snap->crls : nullptr;
	/* no snapshot: an empty list, so the check fails with crl_missing */
	if (!crls)
		crls = none = sk_X509_CRL_new_null();
	X509_STORE_CTX_set0_crls(x, crls);
	X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(x),
				X509_V_FLAG_CRL_CHECK);
	int ok = X509_verify_cert(x);
	X509_STORE_CTX_set0_crls(x, nullptr);
	sk_X509_CRL_free(none);
	return ok > 0 ? 1 : 0;
}

QString isoTime(const ASN1_TIME *t)
{
	struct tm tm {};
	if (!t || ASN1_TIME_to_tm(t, &tm) != 1)
		return QString();
	char buf[32];
	std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
	return QString::fromLatin1(buf);
}

/* All certificates of a PEM file */
std::vector<X509 *> readCerts(const QString &file)
{
	std::vector<X509 *> certs;
	QByteArray name = file.toLocal8Bit();
	BIO *bio = BIO_new_file(name.constData(), "r");
	if (!bio)
		return certs;
	while (X509 *c = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr))
		certs.push_back(c);
	BIO_free(bio);
	ERR_clear_error();
	return certs;
}

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
		st->verifyCode = X509_STORE_CTX_get_error(x);
		st->verifyError = QString::fromUtf8(
			X509_verify_cert_error_string(st->verifyCode));
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
	r.reason = revocationReason(st->verifyCode);
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
	/* the CRLs of tls.client_crl in every chain check (BTD-313) */
	SSL_CTX_set_cert_verify_callback(ctx, verifyWithCrls, nullptr);
	SSL_CTX_set_info_callback(ctx, infoCallback);
	ERR_clear_error();
	return true;
}

ClientCrls::~ClientCrls()
{
	sk_X509_CRL_pop_free(crls, X509_CRL_free);
}

std::shared_ptr<const ClientCrls> loadClientCrls(const QString &crlFile,
		const QString &caFile, QString *message)
{
	std::vector<X509 *> cas = readCerts(caFile);
	auto freeCas = [&cas]() {
		for (X509 *c : cas)
			X509_free(c);
	};
	auto refuse = [&](const QString &m) {
		*message = m;
		freeCas();
		ERR_clear_error();
		return std::shared_ptr<const ClientCrls>();
	};
	if (cas.empty())
		return refuse(QObject::tr("no CA certificate in the client "
			"CAs '%1'").arg(caFile));
	auto set = std::make_shared<ClientCrls>();
	set->crls = sk_X509_CRL_new_null();
	QByteArray name = crlFile.toLocal8Bit();
	BIO *bio = BIO_new_file(name.constData(), "r");
	if (!bio || !set->crls) {
		BIO_free(bio);
		return refuse(QObject::tr("'%1' cannot be read")
				.arg(crlFile));
	}
	std::vector<bool> covered(cas.size(), false);
	const ASN1_TIME *earliest = nullptr;
	while (X509_CRL *crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr,
							nullptr)) {
		if (!sk_X509_CRL_push(set->crls, crl)) {
			X509_CRL_free(crl);
			BIO_free(bio);
			return refuse(QObject::tr("out of memory"));
		}
		QString issuer = rfc4514(X509_CRL_get_issuer(crl));
		size_t i = 0;
		for (; i < cas.size(); i++)
			if (!X509_NAME_cmp(X509_CRL_get_issuer(crl),
					X509_get_subject_name(cas[i])) &&
			    X509_CRL_verify(crl, X509_get0_pubkey(cas[i])) == 1)
				break;
		if (i == cas.size()) {
			BIO_free(bio);
			return refuse(QObject::tr("the CRL of '%1' is not "
				"signed by a CA of '%2'").arg(issuer, caFile));
		}
		if (covered[i]) {
			BIO_free(bio);
			return refuse(QObject::tr("two CRLs of '%1'")
					.arg(issuer));
		}
		covered[i] = true;
		const ASN1_TIME *last = X509_CRL_get0_lastUpdate(crl);
		const ASN1_TIME *next = X509_CRL_get0_nextUpdate(crl);
		if (!next) {
			BIO_free(bio);
			return refuse(QObject::tr("the CRL of '%1' has no "
				"nextUpdate").arg(issuer));
		}
		time_t now = std::time(nullptr);
		/* ASN1_TIME_cmp_time_t: -1 before, 0 equal, 1 after, -2 error */
		if (ASN1_TIME_cmp_time_t(next, now) != 1) {
			BIO_free(bio);
			return refuse(QObject::tr("the CRL of '%1' expired at "
				"%2").arg(issuer, isoTime(next)));
		}
		int lastCmp = last ? ASN1_TIME_cmp_time_t(last, now) : -2;
		if (lastCmp == 1 || lastCmp == -2) {
			BIO_free(bio);
			return refuse(QObject::tr("the CRL of '%1' is not valid "
				"before %2").arg(issuer, isoTime(last)));
		}
		if (!earliest || ASN1_TIME_compare(next, earliest) < 0)
			earliest = next;
	}
	BIO_free(bio);
	/* the loop ends at the end of the file or at data that is no CRL */
	unsigned long err = ERR_peek_last_error();
	ERR_clear_error();
	if (err && ERR_GET_REASON(err) != PEM_R_NO_START_LINE)
		return refuse(QObject::tr("'%1' holds data that is no PEM "
			"CRL").arg(crlFile));
	for (size_t i = 0; i < cas.size(); i++)
		if (!covered[i])
			return refuse(QObject::tr("no CRL of the client CA "
				"'%1' in '%2'").arg(rfc4514(
				X509_get_subject_name(cas[i])), crlFile));
	set->nextUpdate = isoTime(earliest);
	freeCas();
	return set;
}

void setClientCrls(std::shared_ptr<const ClientCrls> crls)
{
	std::lock_guard<std::mutex> lock(crlMutex);
	crlSnapshot = std::move(crls);
}

std::shared_ptr<const ClientCrls> clientCrls()
{
	std::lock_guard<std::mutex> lock(crlMutex);
	return crlSnapshot;
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
