# Migrating `tools.json` to the explicit `args` allow-list (audit F-02)

**Who is affected:** anyone running `python -m app.mcp_proxy --config tools.json` (stdio) or `python -m app.mcp_http_proxy
--config tools.json` (HTTP) with a mapping written before this change. **Behaviour change:** a mapped tool **must** now
declare an `args` allow-list. Old entries fail at startup (exit code 1); they are never silently accepted.

## Why
The Gate evaluates exactly **one destination** (`dest_arg`) and **one method** (`method` from the mapping). If an upstream
tool also accepted a second destination (`endpoint`, `callback_url`, ...) or a method override, the Gate would authorise
something other than what runs. The allow-list guarantees that the arguments the Gate digested and authorised are the only
arguments the upstream receives.

## Before / after
```jsonc
// BEFORE (now rejected at startup)
{"tools": {"fetch": {"tool": "http", "method": "GET", "dest_arg": "url"}}}

// AFTER
{"tools": {"fetch": {"tool": "http", "method": "GET", "dest_arg": "url", "args": ["url"]},
           "read_file": {"tool": "file.read", "dest_arg": "path", "args": ["path"]}}}
```

## How to choose `args`
1. List what the upstream tool actually accepts (the `inputSchema.properties` of `tools/list`):
   `jq '.result.tools[] | {name, props: (.inputSchema.properties // {} | keys)}' tools-list-response.json`
2. `args` must be the **complete** set of arguments you want callers to be able to pass. Include `dest_arg`.
3. Leave out every argument you do not need. Unlisted arguments are refused, never dropped.
4. **If the tool has more than one destination-like argument** (two URLs, a URL plus a webhook, a `host` plus a `path`) it
   cannot be mapped safely: leave it **unmapped** and it stays default-denied (R8). Do not list the second destination.
5. Do not list a method-like argument (`method`, `http_method`, `verb`). The mapping's `method` is what the Gate evaluates.
6. Values must be scalars (string, number, boolean, null). Objects and arrays are refused because they could hide a second
   destination.

## Errors you may see
| Where | Message / rule | Meaning |
|---|---|---|
| startup | `tools.json: <tool>: an explicit non-empty 'args' allow-list is required` | old-style entry; add `args` |
| startup | `... 'args' must contain dest_arg` | add the destination argument to `args` |
| startup | `... destination-like argument 'endpoint' is ambiguous with dest_arg` | a second destination in `args`; remove it or leave the tool unmapped |
| startup | `... method-like argument 'method' is ambiguous with the mapped method` | remove it from `args` |
| startup | `... names that differ only by case/separators` | e.g. `url` and `URL` both listed |
| call | rule `ARGS_POLICY_ARG_NOT_ALLOWED_<name>` | the caller sent an argument outside `args`; nothing reached the Gate or the upstream |
| call | `ARGS_POLICY_ARG_NOT_SCALAR_<name>` | nested value refused |
| call | `ARGS_POLICY_DESTINATION_MISSING_OR_NOT_A_STRING` | `dest_arg` absent, empty or not a string |
| call | `ARGS_POLICY_INVALID` | the running mapping has no valid `args` (only reachable if a mapping is swapped in after construction: both proxy constructors reject such mappings) |

## Verify after migrating
* Start the proxy: a bad file exits with `tools.json: ...` and code 1; a good file starts.
* Run with `--coverage-file cov.json`, call `tools/list`, and read `cov.json`: a tool appears under `gate_evaluated` only if
  its mapping is valid; anything else is under `default_denied`.
* Send one call with an extra argument and confirm it is refused with `ARGS_POLICY_ARG_NOT_ALLOWED_*` and that the upstream
  log shows no request.

## Limits (honest)
* The destination-like check is **name-based**. List only arguments the tool genuinely treats as data.
* Values of allowed non-destination arguments are not interpreted by the Gate (a `text` value that contains a URL is the
  tool's concern).
* A call refused by the argument policy leaves **no Gate decision record** (the Gate was not asked); an E1 adapter report is
  still sent if a reporter is configured.
