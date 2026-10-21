"""
Descoberta de hosts Windows via LDAP (Active Directory).
Ex.: domain=safelabs.lab, ou=Servers,dc=safelabs,dc=lab -> lista de FQDNs.
"""
from typing import List, Optional


def domain_to_base_dn(domain: str) -> str:
    """Converte domínio 'safelabs.lab' em 'DC=safelabs,DC=lab'."""
    if not domain or not domain.strip():
        return ""
    parts = domain.strip().rstrip(".").split(".")
    return ",".join("DC=" + p for p in parts if p)


def build_ldap_base(domain: str, ou: Optional[str] = None) -> str:
    """
    Constrói o search_base LDAP.
    - domain: safelabs.lab -> DC=safelabs,DC=lab
    - ou: "Servers" -> OU=Servers,DC=safelabs,DC=lab
    - ou: "OU=Servers,DC=safelabs,DC=lab" -> usa como está (se já contém DC=)
    """
    base_dn = domain_to_base_dn(domain)
    if not base_dn:
        raise ValueError("Domínio inválido ou vazio")
    if not ou or not ou.strip():
        return base_dn
    ou = ou.strip()
    if "DC=" in ou.upper():
        return ou
    return "OU=" + ou + "," + base_dn


def discover_hosts_ldap(
    domain: str,
    ou: Optional[str] = None,
    ldap_server: Optional[str] = None,
    bind_user: Optional[str] = None,
    bind_password: Optional[str] = None,
    use_ssl: bool = False,
    port: Optional[int] = None,
) -> List[str]:
    """
    Descobre computadores no AD via LDAP. Retorna lista de FQDNs (dNSHostName).
    - domain: ex. safelabs.lab
    - ou: ex. "Servers" ou "OU=Servers,DC=safelabs,DC=lab"
    - ldap_server: ex. dc01.safelabs.lab (se None, tenta primeiro DC do domínio)
    - bind_user: user@domain ou DOMAIN\\user
    - bind_password: senha para bind
    """
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE
        from ldap3.core.exceptions import LDAPException
    except ImportError:
        raise RuntimeError("Descoberta LDAP exige 'ldap3'. Instale: pip install ldap3")

    base_dn = build_ldap_base(domain, ou)
    if not ldap_server or not ldap_server.strip():
        # Fallback: primeiro label do domínio como hostname (ex: dc01.safelabs.lab)
        first = domain.split(".")[0]
        ldap_server = first + "." + domain if first else domain
    server = Server(
        ldap_server,
        port=port or (636 if use_ssl else 389),
        use_ssl=use_ssl,
        get_info=ALL,
    )
    conn = Connection(
        server,
        user=bind_user,
        password=bind_password or "",
        auto_bind=True,
    )
    hostnames: List[str] = []
    try:
        # objectCategory=computer; excluir desabilitados (userAccountControl & 2)
        search_filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["dNSHostName", "cn", "sAMAccountName"],
        )
        for entry in conn.entries:
            fqdn = None
            if hasattr(entry, "dNSHostName") and entry.dNSHostName:
                v = entry.dNSHostName.value
                fqdn = (v[0] if isinstance(v, list) else v)
                fqdn = str(fqdn).strip() if fqdn else None
            if not fqdn and hasattr(entry, "cn") and entry.cn:
                cn = str(entry.cn.value).strip() if entry.cn.value else ""
                if cn and domain:
                    fqdn = cn + "." + domain if "." not in cn else cn
            if fqdn and fqdn not in hostnames:
                hostnames.append(fqdn)
    finally:
        conn.unbind()
    return sorted(hostnames)
