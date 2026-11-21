# The .kh request format

`format: 1` — frozen at Phase 1 completion. Every file must declare it.

A `.kh` file is YAML frontmatter, a line containing only `---`, then the raw
request body. The body is preserved byte for byte; only UI edits rewrite it.

```yaml
format: 1
name: Login
method: POST
url: "{{base_url}}/auth/login"
headers:
  Content-Type: application/json
auth:
  type: none
fuzz:
  targets:
    - body.email
    - header.X-Forwarded-For
spec:
  source: "../openapi.yaml"
  operation: "/auth/login post"
---
{"email": "user@example.com", "password": "secret"}
```

## Fields

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `format` | yes | int | Must be `1` |
| `name` | yes | string | Human-readable, used for report titles and baseline file names |
| `method` | yes | string | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS |
| `url` | yes | string | Supports `{{variable}}` interpolation |
| `headers` | no | map | Header name → value |
| `query` | no | map | Query parameter → value |
| `auth` | no | object | See below |
| `fuzz` | no | object | See below |
| `spec` | no | object | See below |
| `timeout_ms` | no | int | Default 30000 |
| `follow_redirects` | no | bool | Default true |

Unknown fields are **accepted with a warning**, never rejected, so a file
written by a newer build still runs.

## Auth

```yaml
auth: {type: none}
auth: {type: basic, username: "{{user}}", password: "{{pass}}"}
auth: {type: bearer, token: "{{token}}"}
auth: {type: api_key, in: header, name: X-API-Key, value: "{{api_key}}"}
```

`api_key` requires `in` (`header` or `query`) and `name`.

## Fuzz

```yaml
fuzz:
  targets:
    - body.user.email      # JSON body field (dot path, array indices are numbers)
    - query.q
    - header.User-Agent
    - path.1
  wordlist: default        # "default" or a path to a custom wordlist
  methods: [injection, boundary, type_confusion]
  max_requests: 500        # default 500
  rate_limit: 5            # requests/second, default 5
  per_host_concurrency: 2  # in-flight requests per host, default 2
```

### Target rules

- `body.<path>` resolves **only when the body is JSON**. On a multipart or
  form-urlencoded body the parser emits one warning and skips every `body.*`
  target; the run continues with the remaining targets. Multipart and form body
  fuzzing is out of scope for v1 (`project.md` §4.2, R13).
- `path.N` counts **URL path segments only** — scheme, host, port, the leading
  slash and the query string are not segments, and `{{base_url}}` is resolved
  before indexing. For `/users/{{id}}/posts`, `path.0` = `users`, `path.1` = the
  resolved id, `path.2` = `posts`. An index beyond the segment count is a
  warning and the target is skipped.
- Malformed targets (`bdy.email`, `path.-1`, `cookies.sid`) are warnings and are
  skipped — they never abort the run.

### Mutation is in-memory only

Fuzz payloads are applied to a copy of the request in memory. The `.kh` file on
disk is never modified by a fuzz run. "Preserve formatting" applies to UI edits,
which go through the serializer.

## Spec

```yaml
spec:
  source: "../openapi.yaml"           # relative to the .kh file, or absolute
  operation: "/users/{id} get"        # optional; inferred from method + URL path when omitted
  baseline: ".kilhook/last-good.json" # optional; also used by --update-baseline
```

`spec.source` is parsed by kin-openapi (parse only). Response validation is done
by santhosh-tekuri/jsonschema, which owns the schema rules.

`spec.baseline` is resolved relative to the `.kh` file and **must stay inside its
directory tree**. A path in the file cannot point outside the workspace, because
`--update-baseline` writes a response body to that path: a shared or downloaded
request file must not be able to overwrite `.bashrc` on the machine that runs it.
For a baseline somewhere else, pass `--baseline` on the command line — that is
the user typing the path, so it is allowed to go anywhere.

`spec.operation` pins the operation; without it the matched path is derived from
the resolved URL. If the request carries a server base path the spec does not
declare, up to two leading segments are dropped to find a match, and the report
notes that it happened.

## Environments

Environment files are flat YAML maps, loaded from `.kilhook/env/<name>.yaml`
next to the request file (or `--env-file`):

```yaml
base_url: "http://localhost:8080"
token: "eyJ..."
```

All `{{name}}` placeholders in the URL, headers, query, auth fields and body are
resolved before the request is sent. Every missing name is reported at once.

## Versioning policy

- `format: 1` is frozen. Breaking changes require `format: 2` plus a migration tool.
- New **optional** keys do not bump the version.
- The parser warns on unknown fields and continues.
- Multipart/form body fuzzing is a v1 scope cut, not a format change; revisiting
  it requires a real user case and a `format: 2` discussion.
