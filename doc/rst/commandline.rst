
Commandline
===========

XCA can be used without GUI to analyze PKI items and to generate CRLs and
keys. In this case no X-Server connection is required (Linux)

Arguments
---------

.. include:: arguments.rst

Import
------

``--import`` stores every item it can read from the given files. If a file
cannot be read (it is missing or unreadable, or holds no PKI data), the readable
items are still imported. The command then reports each failed file and exits
with code 1.

- The report is an error with the code ``unreadable_input`` or ``no_pki_data``.
  With ``--json`` it is one error object per file on standard error.
- The audit log has one ``object.import`` entry with result ``failure`` for
  each failed file, with the file and the code.

Before bxc-pki BTD-270, an import with an unreadable file exited with 0 and
only printed a warning.

Database password in the GUI
----------------------------

A password given with ``--password`` is always read and compared with the
stored one, also in the GUI and also when the database has an empty password.
If it does not match, XCA shows "Password verify error" and then the unlock
dialog, instead of opening the database without checking the given password.

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
attributes. Because the signed request contains it, a request with a
challenge password has no embedded PEM; its document says
``"challenge_password_present": true`` instead. The raw request is still
available with ``--pem`` (or ``--pem-file``) and ``--select`` without
``--json``.
