# Semgrep Pro Engine

*Lightweight static analysis for many languages. Find bug variants with patterns that look like source code.*

**Homepage**: https://semgrep.dev/

**Version**: `1.128.1`

**Licence**: [`Semgrep Rules License v. 1.0`](https://semgrep.dev/legal/rules-license/)

**Overview**:
- ✅ The tool is free to use under the terms of its license
- ✅ Sharing of analysis results is permitted

**Configuration**:
- Language specific: `--config "p/LANG"`

**Note**: 
- A Semgrep account is needed to access pro engine and pro rules
- An internet connexion is required
- Semgrep Pro Engine needs to be installed:
  ```bash
  # Pro engine requires users to be logged in
  semgrep login
  semgrep install-semgrep-pro

  # Scan using Pro engine with --pro
  semgrep scan --config="p/java" --pro --metrics=off
  ```