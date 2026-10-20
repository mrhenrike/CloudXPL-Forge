<p align="center">
  <strong>CloudXPL-Forge (CXF)</strong><br>
  Cloud Security Assessment Framework
</p>

<p align="center">
  <a href="https://github.com/mrhenrike/CloudXPL-Forge/actions"><img src="https://github.com/mrhenrike/CloudXPL-Forge/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-%3E%3D3.12-blue" alt="Python >= 3.12">
  <img src="https://img.shields.io/badge/modules-508-green" alt="508 Modules">
  <img src="https://img.shields.io/badge/categories-20-purple" alt="20 Categories">
  <img src="https://img.shields.io/badge/version-4.2.0-orange" alt="v4.2.0">
</p>

## Overview

CloudXPL-Forge is the cloud security component of the [XPL-Suite](https://github.com/mrhenrike). It provides 508 modules across 20 categories for AWS, Azure, GCP, Kubernetes, serverless, container and multi-cloud security assessment.

## Categories

AWS, Azure, GCP, Kubernetes, multi-cloud, IAM, serverless, container, storage, network, compute, database, secrets, compliance, monitoring, incident response, forensics, cost, governance, misconfiguration.

## Requirements

- Python >= 3.12
- [xpl-core](https://github.com/mrhenrike/xpl-core) >= 0.3.0
- [xpl-intel](https://github.com/mrhenrike/xpl-intel) >= 2.0.0

## Installation

```bash
pip install cloudxpl
```

Or from source:

```bash
git clone https://github.com/mrhenrike/CloudXPL-Forge.git
cd CloudXPL-Forge
pip install -e ".[dev]"
```

## Quick Start

```bash
cloudxpl --help
cloudxpl scan aws -p default
cloudxpl enumerate k8s --context my-cluster
```

## Testing

```bash
pytest tests/ -q
```

## License

See [LICENSE](LICENSE) for details.

## Author

**Andre Henrique de Oliveira** ([@mrhenrike](https://github.com/mrhenrike)) | [Uniao Geek](https://uniaogeek.com.br)

Part of the [XPL-Suite](https://github.com/mrhenrike) ecosystem.
