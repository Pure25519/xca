
Commandline
===========

XCA can be used without GUI to analyze PKI items and to generate CRLs and
keys. In this case no X-Server connection is required (Linux)

Arguments
---------

.. include:: arguments.rst

JSON output
-----------

With ``--json`` the options ``--print``, ``--list-items``, ``--issuers``,
``--index`` and ``--hierarchy`` print JSON documents that follow the bxc-pki
schemas (certificate, csr, crl, key, template, list) instead of text.

Standard output carries JSON Lines: every document is one line of its own,
so several options or several items of ``--print`` give several lines that a
reader parses line by line. The output is never one JSON array. Each document
names its schema in the member ``schema``, e.g.
``urn:bxc-pki:schema:certificate:v1``.

For ``--index`` and ``--hierarchy`` the file name ``-`` writes the document to
standard output; any other name writes that one document to a JSON file.
``--hierarchy`` then writes one document for all CAs, not a directory.

Messages go to standard error. An error is written to standard error as one
error object (``urn:bxc-pki:schema:error:v1``) and the exit code is 1.

Key documents hold the public key only; no private key, key password or PIN
is printed. The challenge password of a request is left out of its
attributes, but stays inside the embedded PEM of the request.
