/* vi: set sw=4 ts=4:
 *
 * Certificate signing requests without the GUI (BTD-32).
 */

#include "request.h"

#include "pki_key.h"
#include "pki_x509.h"

extList RequestSpec::buildExtensions() const
{
	X509V3_CTX ctx{};
	pki_x509 ctxCert;

	ctxCert.setSubject(subject);
	ctxCert.setIssuer(subject);
	if (key)
		ctxCert.setPubKey(key);
	ctxCert.setSerial(a1int(1L));

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, ctxCert.getCert(), ctxCert.getCert(),
			NULL, NULL, 0);

	/* A request is its own issuer here: the authority key identifier
	 * and issuer:copy have no meaning yet, pki_x509req::createReq()
	 * drops both anyway */
	extList el = extensions.build(&ctx, true, true);
	el += copiedExtensions;
	el.delInvalid();
	return el;
}
