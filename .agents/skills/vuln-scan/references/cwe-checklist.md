# CWE checklist

What to look for, per weakness, when triaging a lead. "Safe pattern" is what
makes a lead a false positive.

| CWE | Name | Typical sinks | Check | Safe pattern |
|---|---|---|---|---|
| CWE-89 | SQL injection | `execute`, `prepare`, `query`, `raw`, ORM `.raw()` / `text()` | Is the SQL string built with f-strings, `%`, `+`, template literals or `.format`? | Placeholders (`?`, `%s`, `:name`) with values passed separately. |
| CWE-78 / 77 | OS command injection | `subprocess(..., shell=True)`, `os.system`, `os.popen`, Node `exec`/`execSync` | Does a shell parse a string containing input? | Argument list without a shell (`subprocess.run([...])`, `execFile`), plus input validation. |
| CWE-22 | Path traversal | `open`, `send_file`, `sendFile`, `fs.readFile`, `createReadStream` | Can `../`, absolute paths or encoded separators reach the path? | `send_from_directory`, `res.sendFile(name, {root})`, `basename` + `resolve` + "starts with base dir" check. |
| CWE-79 | Cross-site scripting | `res.send` with HTML, `innerHTML`, `|safe`, `Markup`, `dangerouslySetInnerHTML` | Is input written into HTML without context-aware escaping? | Auto-escaping templates, `escape()` for the right context, `res.json` for data. |
| CWE-1336 / 94 | Template injection | `render_template_string`, `Template(...)`, `new Function`, `eval` | Does input become part of the template **source** (not a variable)? | Constant template, input passed as a context variable. |
| CWE-95 | Eval injection | `eval`, `Function`, `vm.run*`, Python `eval`/`exec` | Any input in the evaluated string? | A real parser or a lookup table, never `eval`. |
| CWE-502 | Insecure deserialisation | `pickle.loads`, `yaml.load` (unsafe loader), `marshal`, Java `readObject`, `node-serialize` | Can a client supply the serialised bytes (cookie, body, file)? | JSON; `yaml.safe_load`; signed and verified payloads. |
| CWE-918 | SSRF | `requests.*`, `urllib`, `httpx`, `fetch`, `axios`, `http.get` | Does input control the scheme, host or port? Are redirects followed? | Host allowlist, block private/link-local IPs **after DNS resolution**, no redirects. |
| CWE-601 | Open redirect | `redirect(...)`, `res.redirect` | Can input set an absolute URL or `//host`? | Relative paths only, or allowlisted hosts. |
| CWE-1321 | Prototype pollution | Recursive merge/clone/set-by-path helpers, `_.merge`, `_.set`, `Object.assign` on parsed JSON | Are `__proto__`, `constructor`, `prototype` keys copied from user input? | Skip those keys, use `Object.create(null)` or `Map`, or a patched library. |
| CWE-798 | Hardcoded credentials | Assignments and config objects | Is a real-looking secret in source (not a placeholder, not test-only)? | Environment variables or a secret manager; rotate anything committed. |
| CWE-328 / 916 | Weak password hashing | `md5`, `sha1`, plain `sha256` for passwords | Is it used for **passwords** (not checksums or cache keys)? | argon2id, bcrypt, scrypt, PBKDF2 with a high work factor. |
| CWE-489 | Debug features in production | `app.run(debug=True)`, `DEBUG = True`, verbose error handlers | Can the debug setting be on where untrusted users reach it? | Debug off by default, enabled only by local env var. |
| CWE-1395 | Vulnerable dependency | `requirements.txt`, `package.json`, lockfiles | Is the pinned version inside an advisory's affected range? Is the vulnerable API used? | Upgrade to the fixed version; note if the vulnerable function isn't called. |
