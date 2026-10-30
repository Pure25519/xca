/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __FUNC_BASE_H
#define __FUNC_BASE_H

#include <QByteArray>
#include <QIODevice>
#include <QMap>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "base.h"
#include "Passwd.h"
#include <openssl/asn1.h>
#include <openssl/evp.h>

#define IS_GUI_APP (is_gui_app)

class Validity;
extern bool is_gui_app;

QString getFullFilename(const QString &filename, const QString &selectedFilter);
const QStringList getLibExtensions();

QString formatHash(const QByteArray &data, QString sep = ":", int width = 2);
QString compressFilename(const QString &filename, int maxlen = 50);

QString asn1ToQString(const ASN1_STRING *str, bool quote = false);
/* Throws serviceError("invalid_string") for a character the string types
 * of nid cannot hold */
ASN1_STRING *QStringToAsn1(QString s, int nid);
/* serviceError("invalid_string"): s is no valid value of nid, e.g. too
 * long; the message names both and the OpenSSL reasons (BTD-95) */
[[noreturn]] void throwInvalidString(const QString &s, int nid);

QByteArray Digest(const QByteArray &data, const EVP_MD *type);

const char *OBJ_ln2sn(const char *ln);
const char *OBJ_sn2ln(const char *sn);
const char *OBJ_obj2sn(ASN1_OBJECT *a);
QString OBJ_obj2QString(const ASN1_OBJECT *a, int no_name = 0);

extern QMap<int, QString> dn_translations;
void dn_translations_setup();
#define openssl_error_msg(x) _openssl_error(QString(x), __FILE__, __LINE__)
#define openssl_error() openssl_error_msg("")
#define ign_openssl_error() _ign_openssl_error(QString(), __FILE__, __LINE__)
void _openssl_error(const QString &txt, const char *file, int line);
bool _ign_openssl_error(const QString &txt, const char *file, int line);
/* The reasons of the OpenSSL error queue with their data strings, one per
 * line, "unknown OpenSSL error" for an empty queue; empties the queue */
QString take_openssl_errors();
/* A boolean setting of an OpenSSL provider (openssl.cnf), read as the
 * provider reads it: 1, yes, true, on and 0, no, false, off (case does
 * not matter for the words); anything else or NULL gives dflt */
bool openssl_bool(const char *value, bool dflt);

/* Test hooks of the OpenSSL encoders (BTD-199), off in production and set
 * by tests only. bioWrites: BioByteArray::bio() hands out a read-only
 * memory BIO, so every encoder writing into it fails as OpenSSL does.
 * i2d: i2d_bytearray() sees an encoder that returns -1. */
namespace encodeFault
{
	extern bool bioWrites;
	extern bool i2d;
}

/* The DER of data; throws serviceError encoding_failed with the OpenSSL
 * reason instead of returning empty or short DER (BTD-199) */
QByteArray i2d_bytearray(int(*i2d)(const void*, unsigned char**), const void*);

/* The result of an OpenSSL encoder of an export (BTD-199): 1 or more is
 * success, anything else throws serviceError export_failed naming the
 * encoder, the object (what) and the OpenSSL reason */
void export_check(int ok, const char *encoder, const QString &what);
/* Writes the encoded bytes of an export; empty or short output throws
 * serviceError export_failed (BTD-199) */
void export_write(QIODevice &file, const QByteArray &data,
		const QString &what);
void *d2i_bytearray(void *(*d2i)(void*, unsigned char**, long),
		QByteArray &ba);

#define I2D_VOID(a) ((int (*)(const void *, unsigned char **))(a))
#define D2I_VOID(a) ((void *(*)(void *, unsigned char **, long))(a))

QString appendXcaComment(QString current, QString msg);

QString get_ossl_verify_error(int err);
QString toHexBlock(const QByteArray &ba);

/* from version.cpp */
const char *version_str(bool html);

#endif
