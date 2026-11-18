# Security policy

Pondhawk.Waf is security software. A way to get an attack past it (a bypass), to crash it, or to make it use
excessive CPU or memory is a vulnerability. Please report it privately.

## Reporting

Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then **Report a
vulnerability**. Do not open a public issue.

Include:

- the request (raw HTTP if possible) and the application endpoint that receives it;
- the Pondhawk.Waf version and the options (profile, paranoia level, rule engine mode);
- what you expected the WAF to do, and what it did.

We acknowledge reports within 5 working days and agree a disclosure date with you once a fix is ready.

## Scope

In scope:

- Requests that the application receives with a payload the WAF did not inspect: parsing differences with ASP.NET
  Core (query string, form, multipart, JSON, XML, headers, cookies), body limit bypasses, response leaks that pass
  inspection.
- Inspection of a CRS rule that differs from the reference (Coraza or ModSecurity) in a way that misses an attack.
- Denial of service through the WAF: requests whose inspection costs disproportionate CPU or memory.
- Credentials or other sensitive data written to the logs.

Out of scope (report to the [OWASP CRS project](https://github.com/coreruleset/coreruleset/security) instead):

- Payloads that CRS itself does not detect at the configured paranoia level, when Coraza or ModSecurity with the
  same CRS version and settings do not detect them either.

Known limits are listed in the README ("Limits and failure behavior") and in docs/DESIGN.md ("Known differences
from Coraza").

## Supported versions

Only the latest released version receives security fixes.
