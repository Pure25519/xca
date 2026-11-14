#!/usr/bin/env python3
"""Generates server/roles.json from the bxc-pki api/openapi.yaml (BTD-155).

    gen_roles.py <openapi.yaml> [--source <label>] [--output <roles.json>]
    gen_roles.py <openapi.yaml> --check <roles.json>

roles.json is the operation table of xca-server: one entry per operation of
the OpenAPI document with its method, its path (as in the document, without
the /v1 prefix the server adds), the roles of x-roles and the parameter that
names the CA the operation acts on (ca_param, null for none). It is compiled
into the server; the server checks every request against it.

Role names: the OpenAPI document uses reader, ra_operator, ca_admin and
auditor; xca-server.json (like the bootstrap schema) uses reader,
ra-operator, ca-admin and auditor. roles.json keeps the OpenAPI names; the
server maps a role of xca-server.json to them by replacing '-' with '_'.

ca_param is not part of the OpenAPI document (yet), so CA_PARAMS below lists
it per operation, and the generator checks that the parameter exists:

    path:<name>          the CA certificate itself, named by the path parameter
    path:<name>#issuer   the issuer of the certificate named by the path parameter
    body:<member>        the CA named by a member of the JSON request body

path_params lists the enums of the path parameters (e.g. collection), so the
server matches /keys but not /profiles against /{collection}.

SERVER_ONLY lists operations of the server that are not in the OpenAPI
document: GET /status (BTD-154). They are appended after the document's.

Python 3 standard library only. The YAML parser below reads the subset the
OpenAPI document uses: block mappings, block sequences, flow sequences
([a, b]), quoted and plain scalars, and block scalars (| and >), which it
skips. --check compares a roles.json with what the document gives and exits
1 on a difference (for the comparison test in the bxc-pki repository).
"""

import argparse
import json
import re
import sys

METHODS = ("get", "put", "post", "delete", "patch")
ROLES = ("reader", "ra_operator", "ca_admin", "auditor")

# operationId -> ca_param; every other operation names no CA (null)
CA_PARAMS = {
    "issueCertificate": "body:issuer",
    "generateCrl": "body:issuer",
    "renewCertificate": "path:id#issuer",
    "revokeCertificate": "path:id#issuer",
    "unrevokeCertificate": "path:id#issuer",
    "setRevocations": "path:id",
    "updateCaProperties": "path:id",
    "setTlsAuthKey": "path:id",
    "assignDocument": "path:id",
    "unassignDocument": "path:id",
}

SERVER_ONLY = [
    {"operation_id": "getStatus", "method": "GET", "path": "/status",
     "roles": list(ROLES), "ca_param": None},
]


class YamlError(Exception):
    pass


def _strip_comment(text):
    """Removes a comment outside quotes."""
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def _scalar(text):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [] if not inner else [_scalar(x) for x in inner.split(",")]
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    if text in ("true", "false"):
        return text == "true"
    if text in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?[0-9]+", text):
        return int(text)
    return text


class _Lines:
    def __init__(self, text):
        self.lines = []
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                self.lines.append(None)
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            self.lines.append((indent, _strip_comment(raw.strip())))
        self.pos = 0

    def peek(self):
        while self.pos < len(self.lines) and self.lines[self.pos] is None:
            self.pos += 1
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def skip_block(self, indent):
        """Skips the lines of a block scalar (more indented than indent,
        blank lines included)."""
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line is not None and line[0] <= indent:
                return
            self.pos += 1


def _value(lines, indent, rest):
    """The value after 'key:' or '- ' with the text rest on the line."""
    if rest in ("|", ">", "|-", ">-", "|+", ">+"):
        lines.skip_block(indent)
        return None
    if rest:
        return _scalar(rest)
    nxt = lines.peek()
    if nxt is None or nxt[0] <= indent and not nxt[1].startswith("- "):
        return None
    if nxt[0] < indent:
        return None
    return _node(lines, nxt[0])


def _node(lines, indent):
    first = lines.peek()
    if first[1].startswith("- ") or first[1] == "-":
        return _sequence(lines, indent)
    return _mapping(lines, indent)


def _mapping(lines, indent):
    result = {}
    while True:
        line = lines.peek()
        if line is None or line[0] < indent:
            return result
        if line[0] > indent:
            raise YamlError("unexpected indentation at line %d" % (lines.pos + 1))
        text = line[1]
        if text.startswith("- "):
            return result
        m = re.match(r"""^("[^"]*"|'[^']*'|[^:]+?)\s*:(\s+(.*))?$""", text)
        if not m:
            raise YamlError("not a mapping entry at line %d: %s" % (lines.pos + 1, text))
        key = _scalar(m.group(1))
        lines.pos += 1
        result[key] = _value(lines, indent, (m.group(3) or "").strip())


def _sequence(lines, indent):
    result = []
    while True:
        line = lines.peek()
        if line is None or line[0] < indent:
            return result
        text = line[1]
        if line[0] != indent or not (text.startswith("- ") or text == "-"):
            return result
        rest = text[1:].strip()
        m = re.match(r"""^("[^"]*"|'[^']*'|[^:\[\]]+?)\s*:(\s+(.*))?$""", rest)
        if m:
            # "- key: value" starts a mapping indented by two more
            lines.lines[lines.pos] = (indent + 2, rest)
            result.append(_mapping(lines, indent + 2))
        else:
            lines.pos += 1
            result.append(_value(lines, indent, rest))


def load_yaml(text):
    lines = _Lines(text)
    if lines.peek() is None:
        return {}
    return _node(lines, lines.peek()[0])


def _ref(doc, ref):
    if not ref.startswith("#/"):
        return None
    node = doc
    for part in ref[2:].split("/"):
        node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            return None
    return node


def _properties(doc, schema, seen=()):
    """The property names of a schema, through $ref and allOf."""
    if not isinstance(schema, dict):
        return set()
    if "$ref" in schema:
        if schema["$ref"] in seen:
            return set()
        return _properties(doc, _ref(doc, schema["$ref"]), seen + (schema["$ref"],))
    names = set((schema.get("properties") or {}).keys())
    for sub in schema.get("allOf") or []:
        names |= _properties(doc, sub, seen)
    return names


def _check_ca_param(doc, op_id, path, op, param):
    kind, _, name = param.partition(":")
    name = name.split("#")[0]
    if kind == "path":
        if "{%s}" % name not in path:
            raise SystemExit("%s: ca_param %s: no path parameter {%s} in %s"
                             % (op_id, param, name, path))
        return
    if kind == "body":
        body = (((op.get("requestBody") or {}).get("content") or {})
                .get("application/json") or {}).get("schema")
        if name not in _properties(doc, body):
            raise SystemExit("%s: ca_param %s: the request body has no member %s"
                             % (op_id, param, name))
        return
    raise SystemExit("%s: unknown ca_param kind %s" % (op_id, param))


def _path_params(doc, paths):
    """The enums of the path parameters used in paths."""
    enums = {}
    for path, item in paths.items():
        params = list(item.get("parameters") or [])
        for method in METHODS:
            params += list((item.get(method) or {}).get("parameters") or [])
        for p in params:
            if isinstance(p, dict) and "$ref" in p:
                p = _ref(doc, p["$ref"])
            if not isinstance(p, dict) or p.get("in") != "path":
                continue
            enum = (p.get("schema") or {}).get("enum")
            if enum:
                enums[p["name"]] = [str(v) for v in enum]
    return dict(sorted(enums.items()))


def generate(doc, source):
    paths = doc.get("paths") or {}
    operations = []
    seen = set()
    for path, item in paths.items():
        for method in METHODS:
            op = item.get(method)
            if not op:
                continue
            op_id = op.get("operationId")
            roles = op.get("x-roles")
            if not op_id:
                raise SystemExit("%s %s: no operationId" % (method.upper(), path))
            if not isinstance(roles, list) or not roles:
                raise SystemExit("%s: no x-roles" % op_id)
            unknown = [r for r in roles if r not in ROLES]
            if unknown:
                raise SystemExit("%s: unknown roles %s" % (op_id, unknown))
            ca_param = CA_PARAMS.get(op_id)
            if ca_param:
                _check_ca_param(doc, op_id, path, op, ca_param)
            seen.add(op_id)
            operations.append({"operation_id": op_id, "method": method.upper(),
                               "path": path, "roles": roles, "ca_param": ca_param})
    missing = sorted(set(CA_PARAMS) - seen)
    if missing:
        raise SystemExit("CA_PARAMS names operations the document does not have: %s"
                         % ", ".join(missing))
    for extra in SERVER_ONLY:
        if extra["operation_id"] in seen:
            raise SystemExit("%s is in the document now; remove it from SERVER_ONLY"
                             % extra["operation_id"])
        operations.append(dict(extra))
    return {"source": source, "path_params": _path_params(doc, paths),
            "operations": operations}


def dump(table):
    return json.dumps(table, indent=2, ensure_ascii=False) + "\n"


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("openapi")
    ap.add_argument("--source", default="api/openapi.yaml",
                    help="the source label written to roles.json, e.g. api/openapi.yaml@<commit>")
    ap.add_argument("--output", help="write roles.json here instead of stdout")
    ap.add_argument("--check", metavar="ROLES_JSON",
                    help="compare the operations of this roles.json; exit 1 on a difference")
    args = ap.parse_args(argv)
    with open(args.openapi, encoding="utf-8") as f:
        doc = load_yaml(f.read())
    table = generate(doc, args.source)
    if args.check:
        with open(args.check, encoding="utf-8") as f:
            have = json.load(f)
        if (have.get("operations") != table["operations"] or
                have.get("path_params") != table["path_params"]):
            sys.stderr.write("%s does not match %s\n" % (args.check, args.openapi))
            return 1
        sys.stdout.write("ok: %d operations\n" % len(table["operations"]))
        return 0
    text = dump(table)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
