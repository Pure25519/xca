/* vi: set sw=4 ts=4:
 *
 * The key types of bxc-pki: exactly the vocabulary of the bootstrap file
 * (bxc-pki schemas/bootstrap.schema.json $defs/keyType), also the values
 * of key_types in a profile (schemas/profile.schema.json, BTD-237). One
 * table maps each name onto the keyjob text of the service layer and
 * onto its key family, the key of ku_by_key_type in a profile.
 */

#ifndef __KEY_TYPES_H
#define __KEY_TYPES_H

#include <QString>
#include <QStringList>

#include <openssl/types.h>

/* A name of the vocabulary (rsa-3072, ec-p256, ed25519, ml-dsa-65, ...)
 * as keyjob text; an unknown name is invalid_key_type, a name this build
 * cannot generate not_supported. Size and curve are checked by the key
 * generation service. */
QString keyJobText(const QString &keyType);
/* The names this build can generate */
QStringList supportedKeyTypes();
/* The name of a key's type; empty when the vocabulary has none */
QString keyTypeOf(const EVP_PKEY *pkey);
/* Every name of the vocabulary, also those this build cannot generate */
QStringList keyTypeNames();
/* The key family of a name: rsa, ec, eddsa, ml-dsa or slh-dsa; empty
 * for a name outside the vocabulary */
QString keyTypeFamily(const QString &keyType);
/* Every key family, in the order of the table */
QStringList keyFamilies();
/* Whether keys of the family only sign (EdDSA, ML-DSA, SLH-DSA): no
 * encryption or key agreement bit, no digest in their signature */
bool signatureOnlyFamily(const QString &family);

#endif
