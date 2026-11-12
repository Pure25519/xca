
Templates
=========

Templates are special to XCA and not interchangeable with other applications.
They store all information to create certificates or requests.

To use templates, just create a new certificate or request and apply one
of the templates (or parts of it) in the *Source* Tab.
Usually you have the distinguished name parts, that never change and
properties (extensions) that define the use of the certificate.
You may apply the whole template or only the subject or only the extensions.

Next to the 3 default templates for CA, TLS server and client
certificates, customized templates may be created. Templates are not signed,
they are just a collection of common values for different certificates.
Therefore XCA does not care if any duplicates exist in the list of templates.

An easy way to create templates is to export an existing certificate or
PKCS#10 request to a template. Just select *Transform->Template*
in the context-menu of the item. The private key of the
Certificate or Request is not required for this operation.

Request merge
-------------

The tab *Request merge* of the template dialog decides what a certificate
request adds when it is signed with the template. For the subject
alternative name, the key usage and the extended key usage it offers:

- *Legacy*: as XCA always did. The request's extension is copied only with
  "copy extensions" and only where the template has none.
- *Template*: the template's extension; the request's is ignored.
- *Request*: the request's extension if it has one, else the template's.
  Device requests may ask for more than they need.
- *Merge*: the entries of both.

*Allowed extended key usages* limits what a request may ask for (comma
separated short names, long names or OIDs; empty: any). *Default extended
key usages* is used for a request that asks for none; each entry must be
allowed. A name OpenSSL does not know, or a default outside the allowed
list, is refused when the template is saved.
