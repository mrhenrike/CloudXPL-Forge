#!/usr/bin/env python3
"""
Test real APT44 IOC containment via MCP servers.
Executa contenção com IOCs reais usando uma única sessão SSH por bloco.
"""
import sys, os, json, importlib.util, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load .env
_env_path = Path(__file__).parent.parent.parent.parent / "laboratory" / "poc-harpia" / ".env"
if _env_path.is_file():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

# Patch sys.path for the MCP dir
mcp_dir = Path(__file__).parent.parent
sys.path.insert(0, str(mcp_dir))

IOC_DIR = mcp_dir / "ioc_lists"


def _read_list(name: str) -> list[str]:
    p = IOC_DIR / f"{name}.txt"
    return [l.split("#")[0].strip() for l in p.read_text(encoding="utf-8-sig").splitlines()
            if l.split("#")[0].strip()]


def _section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def test_fw_containment():
    """Test FortiGate blocking of APT44 IOCs using single SSH session."""
    _section("FortiGate — APT44 IOC Containment")

    spec = importlib.util.spec_from_file_location("server_fw", mcp_dir / "server_fw.py")
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Single SSH session for all ops
    try:
        cli = mod._get_cli()
        print("[OK] SSH conectado ao FortiGate")
    except Exception as e:
        print(f"[SKIP] FortiGate SSH indisponível: {e}")
        return

    results = {"ok": 0, "fail": 0, "actions": []}

    # 1. Block APT44 C2 IPs (top priority — direct C2 infra)
    print("\n[1/4] Bloqueando IPs C2 APT44...")
    apt44_ips = _read_list("apt44_ips")
    for ip in apt44_ips[:10]:  # Test first 10
        try:
            r = cli.block_ip(ip, "APT44 Sandworm C2 — automated containment")
            print(f"  [OK] {r}")
            results["ok"] += 1
            results["actions"].append({"action": "block_ip", "ioc": ip, "status": "ok"})
        except Exception as e:
            print(f"  [ERRO] {ip}: {e}")
            results["fail"] += 1

    # 2. Block C2 domains
    print("\n[2/4] Bloqueando domínios C2 APT44...")
    domains = _read_list("apt44_domains")
    for d in domains:
        try:
            r = cli.block_domain(d)
            print(f"  [OK] {r}")
            results["ok"] += 1
            results["actions"].append({"action": "block_domain", "ioc": d, "status": "ok"})
        except Exception as e:
            print(f"  [ERRO] {d}: {e}")
            results["fail"] += 1

    # 3. Block payload URLs
    print("\n[3/4] Bloqueando URLs de payload...")
    urls = _read_list("apt44_urls")
    for u in urls:
        try:
            r = cli.block_url(u)
            print(f"  [OK] {r}")
            results["ok"] += 1
        except Exception as e:
            print(f"  [ERRO] {u}: {e}")
            results["fail"] += 1

    # 4. Verify blocked IOCs
    print("\n[4/4] Verificando IOCs bloqueados...")
    iocs = cli.list_iocs()
    print(f"  IPs bloqueados: {len(iocs['blocked_ips'])}")
    print(f"  Hosts isolados: {len(iocs['isolated_hosts'])}")

    cli.close()
    print(f"\n  RESULTADO: {results['ok']} OK | {results['fail']} ERROS")
    return results


def test_edr_containment():
    """Test SentinelOne — collect threats and blacklist APT44 hashes."""
    _section("SentinelOne EDR — APT44 Hash Blacklist + IOC Collection")

    spec = importlib.util.spec_from_file_location("server_edr", mcp_dir / "server_edr.py")
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # 1. Status
    print("\n[1/3] Status SentinelOne...")
    status = mod.edr_status()
    print(f"  {status[:200]}")

    # 2. List active threats
    print("\n[2/3] Threats não resolvidos...")
    threats_json = mod.edr_list_threats(unresolved_only=True)
    try:
        threats = json.loads(threats_json)
        print(f"  Total threats ativos: {len(threats)}")
        for t in threats[:3]:
            print(f"  - [{t.get('classification','?')}] {t.get('threat_name','?')} | host={t.get('agent_name','?')} | sha1={t.get('sha1','N/A')[:20]}")
    except Exception:
        print(f"  {threats_json[:300]}")

    # 3. Blacklist APT44 hashes
    print("\n[3/3] Adicionando hashes APT44 à blacklist S1...")
    result = mod.edr_blacklist_hash_list("apt44_hashes")
    print(f"  {result[:500]}")


def test_ad_dns_containment():
    """Test AD user check + DNS domain blocking."""
    _section("AD/DNS — APT44 Domain Sinkhole + Cert Store Check")

    spec = importlib.util.spec_from_file_location("server_ad_dns", mcp_dir / "server_ad_dns.py")
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # 1. DNS status
    print("\n[1/4] DNS status...")
    try:
        r = mod.dns_status()
        print(f"  {r[:200]}")
    except Exception as e:
        print(f"  [SKIP] {e}")

    # 2. Block APT44 domains via DNS sinkhole
    print("\n[2/4] Bloqueando domínios APT44 via DNS sinkhole...")
    domains = _read_list("apt44_domains")
    for d in domains[:5]:
        try:
            r = mod.dns_block_domain(d)
            data = json.loads(r)
            status = "OK" if data.get("ok") else "SKIP/EXISTE"
            print(f"  [{status}] {d} → sinkhole 0.0.0.0")
        except Exception as e:
            print(f"  [ERRO] {d}: {e}")

    # 3. List blocked domains
    print("\n[3/4] Domínios bloqueados no DNS...")
    try:
        r = mod.dns_list_blocked()
        data = json.loads(r)
        print(f"  Total bloqueados: {data.get('count', '?')}")
        for d in data.get("blocked_domains", [])[:10]:
            print(f"  - {d}")
    except Exception as e:
        print(f"  [SKIP] {e}")

    # 4. Check cert store for DemiMur technique
    print("\n[4/4] Verificando Certificate Store (técnica DemiMur APT44)...")
    try:
        r = mod.ad_dns_check_certificate_store_modification()
        data = json.loads(r)
        n = data.get("suspicious_certs", 0)
        print(f"  Certificados suspeitos: {n}")
        if n > 0:
            print("  ⚠ ALERTA: Certificado raiz não-Microsoft encontrado!")
            for c in data.get("certs", []):
                print(f"    Subject: {c.get('Subject','?')}")
                print(f"    Added:   {c.get('NotBefore','?')}")
        else:
            print(f"  ✓ {data.get('note','OK')}")
    except Exception as e:
        print(f"  [SKIP] {e}")


def main():
    print("SafeLabs MCP — APT44 IOC Containment Test")
    print(f"IOC Lists: {IOC_DIR}")
    print(f"Lists: {[f.name for f in sorted(IOC_DIR.glob('*.txt'))]}\n")

    # Run tests
    test_fw_containment()
    test_edr_containment()
    test_ad_dns_containment()

    print("\n" + "="*60)
    print("  TESTES CONCLUÍDOS")
    print("="*60)


if __name__ == "__main__":
    main()
