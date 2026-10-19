# Security Policy - CloudXPL-Forge

## Scope

CloudXPL-Forge (CXF) is an offensive and defensive security research framework for cloud infrastructure. This policy covers:

- Vulnerabilities in the CXF codebase itself
- Misuse of CXF modules against unauthorized targets

## Authorized Use Only

CXF modules must **only** be used on:

- Cloud accounts you own
- Isolated sandbox environments
- Engagements with **explicit written authorization**

Unauthorized use may violate computer crime laws and cloud provider terms of service.

## Reporting a Vulnerability in CXF

If you find a security issue in the CXF framework (RCE in the CLI, credential leak, etc.):

1. **Do not** open a public GitHub issue for exploitable findings
2. Email: **henrique.santos@uniaogeek.com.br**
3. Include: affected version, reproduction steps, impact assessment
4. Allow **90 days** for remediation before public disclosure

We follow coordinated disclosure.

## Reporting Cloud Provider Vulnerabilities

If CXF helps you discover a vulnerability in a cloud provider:

1. Document in an isolated sandbox account
2. Notify the cloud provider through their security disclosure channel
3. Allow minimum **90 days** for critical issues
4. After disclosure, consider contributing a module via pull request

## Safe Defaults

- Simulate mode enabled by default where applicable
- No credential storage in module code
- Destructive operations require explicit opt-in
- Operations are logged for audit purposes

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.2.x   | Yes       |
| 4.1.x   | Best effort |
| < 4.0   | No        |

Maintainer: Andre Henrique ([@mrhenrike](https://github.com/mrhenrike))
