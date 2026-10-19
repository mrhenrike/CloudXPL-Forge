# Contributing to CloudXPL-Forge

Thank you for your interest in contributing. This project is an offensive and defensive security research tool for cloud infrastructure (AWS, Azure, GCP, multi-cloud).

## Legal Notice

By contributing you confirm that:
- You have authorization to submit the code
- The exploit or module targets systems you own or have explicit written permission to test
- You understand and accept the [project disclaimer](README.md#disclaimer)
- You will not submit modules designed to cause unauthorized harm

## Development Setup

```bash
git clone https://github.com/mrhenrike/CloudXPL-Forge.git
cd CloudXPL-Forge
pip install -e ".[dev]"
python -m cloudxpl
```

## Module Structure

Each module lives under `cloudxpl/modules/<provider>/<category>/` and must:

1. Inherit from the base exploit class
2. Define `__info__` with all required metadata fields
3. Include `simulate = True` as default mode
4. Implement `check()` for target validation
5. Implement `run()` with safety gates before live payloads

## Contribution Checklist

- [ ] `simulate=True` default
- [ ] `check()` returns `bool`
- [ ] `__info__` complete with CVSS, MITRE, CVE
- [ ] No secrets, API keys, or credentials in code
- [ ] Impact level accurate
- [ ] Tested locally with mock or sandbox cloud accounts

## Submitting a Pull Request

1. Fork the repository
2. `git checkout -b add-cve-YYYY-NNNNN`
3. Add your module(s)
4. Run tests: `pytest`
5. Submit PR with clear description

## Module Categories

| Provider | Description |
|----------|-------------|
| `modules/aws/` | AWS exploitation and enumeration |
| `modules/azure/` | Azure/Entra ID exploitation |
| `modules/gcp/` | Google Cloud exploitation |
| `modules/multi/` | Multi-cloud and cross-provider modules |

## Contact

Andre Henrique (@mrhenrike) - henrique.santos@uniaogeek.com.br
