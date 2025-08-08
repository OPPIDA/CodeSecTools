# Semgrep Test Code

*Test code for Semgrep's Community Edition and Pro rules*

**Homepage**: https://github.com/semgrep/semgrep

**Version**: `15/05/2025` (*download date*)

**Licence**: [`Semgrep Rules License v. 1.0`](https://semgrep.dev/legal/rules-license/) (*for both Community Edition and Pro*)

**Scope**: `File`

**Included**: ✅ (Full)

- `Semgrep_all.json`

Community Edition rules are available [here](https://github.com/semgrep/semgrep-rules) but Pro rules are only available in Semgrep AppSec Platform (log in required).

It is possible to download rules and test codes using Semgrep API.

The provided script `downloader.py` downloads all and store in `./datasets/Semgrep/Semgrep_all.json`.

To get the token:

1. Log into your account
2. Open dev tools
3. Navigate to any pages to perform requests
4. Apply filter: `https://semgrep.dev/api`
5. Get the Bearer token from the request header

```bash
$ SEMGREP_TOKEN=YOUR_TOKEN python3 ./datasets/Semgrep/downloader.py
```