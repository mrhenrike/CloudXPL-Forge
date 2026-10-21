# CloudXPL-Forge  -  Hypervisor & VM Escape CVE Research (2019-2026)

> Pesquisa profunda: CVEs, ExploitDB, Metasploit, PoCs públicos e referências.
> Gerado em 2026-10-17 para CloudXPL-Forge v4.0.0 (424 módulos).

---

## 1. VMware ESXi / vCenter (25+ CVEs)

### CVEs Críticos (KEV / CVSS 9.0+)

| CVE | Produto | CVSS | KEV | Tipo | Módulo CXF |
|-----|---------|------|-----|------|------------|
| CVE-2019-5544 | ESXi OpenSLP | 9.8 | Sim | Heap overflow RCE (port 427) | `cve-2019-5544` |
| CVE-2020-3952 | vCenter vmdir | 10.0 |  -  | Auth bypass LDAP | `cve-2020-3952` |
| CVE-2020-3992 | ESXi OpenSLP | 9.8 | Sim | UAF RCE | `cve-2020-3992` |
| CVE-2021-21972 | vCenter | 9.8 | Sim | File upload RCE unauth | `cve-2021-21972` |
| CVE-2021-21974 | ESXi OpenSLP | 8.8 | Sim | Heap overflow RCE (ESXiArgs) | `cve-2021-21974` |
| CVE-2021-21985 | vCenter vSAN | 9.8 | Sim | RCE via Health plugin | `cve-2021-21985` |
| CVE-2021-22005 | vCenter CEIP | 9.8 | Sim | File upload RCE | `cve-2021-22005` |
| CVE-2022-22954 | Workspace ONE | 9.8 | Sim | SSTI RCE | `cve-2022-22954` |
| CVE-2022-31705 | ESXi/WS/Fusion | 9.3 |  -  | EHCI USB OOB VM escape | `cve-2022-31705` |
| CVE-2023-20867 | VMware Tools | 3.9 | Sim | Auth bypass (UNC3886) | `cve-2023-20867` |
| CVE-2023-34048 | vCenter | 9.8 | Sim | DCE/RPC OOB write RCE | `cve-2023-34048` |
| CVE-2024-37085 | ESXi AD | 6.8 | Sim | AD group auth bypass | `cve-2024-37085` |
| CVE-2025-22224 | ESXi VMCI | 9.3 | Sim | TOCTOU heap overflow | `esxi-cve-2025-22224` |
| CVE-2025-22225 | ESXi | 8.2 | Sim | Arbitrary kernel write | `cve-2025-22225` |
| CVE-2025-22226 | ESXi HGFS | 7.1 | Sim | OOB read memory leak | `cve-2025-22226` |

### ExploitDB

| EDB-ID | CVE | Tipo |
|--------|-----|------|
| EDB-48535 | CVE-2020-3952 | vCenter vmdir auth bypass |
| EDB-49602 | CVE-2021-21972 | vCenter file upload RCE |
| EDB-50056 | CVE-2021-21972 | vCenter file upload RCE (v2) |

### Metasploit Modules

| Module | CVE | Descrição |
|--------|-----|-----------|
| `exploit/multi/http/vmware_vcenter_uploadova_rce` | CVE-2021-21972 | OVA upload path traversal |
| `exploit/linux/http/vmware_vcenter_analytics_file_upload` | CVE-2021-22005 | CEIP analytics file upload |
| `exploit/multi/http/vmware_vcenter_vsan_health_rce` | CVE-2021-21985 | vSAN Health plugin RCE |
| `exploit/multi/http/vmware_vcenter_log4shell` | CVE-2021-44228 | Log4Shell JNDI injection |
| `post/multi/gather/vcenter_secrets_dump` |  -  | vCenter secrets extraction |
| `exploit/linux/local/vcenter_sudo_lpe` |  -  | vCenter sudo LPE |
| `post/multi/gather/vcenter_forge_saml_token` |  -  | SAML token forge |
| `auxiliary/admin/vmware/vcenter_offline_mdb_extract` |  -  | MDB offline extraction |

### GitHub PoCs

- `horizon3ai/CVE-2021-21972`  -  vCenter upload RCE
- `NS-Sp4ce/CVE-2021-21972`  -  file upload scanner + exploit
- `xnianq/CVE-2021-21985`  -  vSAN Health RCE
- `alt3kx/CVE-2021-21985`  -  vSAN Health scanner
- `Shadow0ps/CVE-2021-21974`  -  ESXi OpenSLP exploit
- `puzzlepeaches/Log4jCenter`  -  vCenter Log4Shell
- `xairy/vmware-exploitation`  -  curated VMware exploitation list
- `UGF0aWVudF9aZXJv/VMWare-Pentesting`  -  VMware pentesting collection

### Threat Actors

- **UNC3886**: explorou CVE-2023-34048 (desde 2021), CVE-2023-20867 (VMware Tools)
- **Storm-0506, Octo Tempest, Manatee Tempest**: CVE-2024-37085 (ESXi AD bypass)
- **ESXiArgs**: campanha ransomware usando CVE-2021-21974

---

## 2. Microsoft Hyper-V (15+ CVEs)

### Guest-to-Host Escape CVEs

| CVE | CVSS | KEV | Tipo | Módulo CXF |
|-----|------|-----|------|------------|
| CVE-2020-1040 | 9.0 | Sim | RemoteFX vGPU RCE | `hyperv-remotefx` |
| CVE-2020-1036/1032/1041/1042/1043 | 9.0 |  -  | RemoteFX vGPU series | `hyperv-remotefx` |
| CVE-2021-28476 | 9.9 |  -  | vmswitch guest-to-host | `hyperv-cve-2021-28476` |
| CVE-2021-34450 | 9.9 |  -  | Guest-to-host code exec | `hyperv-escape` |
| CVE-2022-30163 | 8.5 |  -  | Race condition escape | `hyperv-cve-2022-30163` |
| CVE-2024-21407 | 8.1 |  -  | Guest-to-host RCE | `hyperv-cve-2024-21407` |
| CVE-2024-20700 |  -  |  -  | Hyper-V RCE | `hyperv-cve-2024-20700` |
| CVE-2024-38080 |  -  |  -  | Hyper-V EoP | `hyperv-cve-2024-38080` |
| CVE-2025-21333/21334/21335 |  -  |  -  | Hyper-V NT kernel EoP | `hyperv-cve-2025-21333` etc |
| CVE-2026-40402 | 9.3 |  -  | UAF guest-to-host | `hyperv-cve-2026-40402` |
| CVE-2026-57092 | 9.9 |  -  | VMSwitch UAF escape | `hyperv-cve-2026-57092` |
| CVE-2026-69603 | 8.8 |  -  | Guest-to-host code exec | `hyperv-cve-2026-69603` |
| CVE-2026-80083 | 8.8 |  -  | Guest-to-host code exec | `hyperv-cve-2026-80083` |
| CVE-2026-72961 | 8.2 |  -  | vTPM state escape | `hyperv-cve-2026-72961` |

### GitHub PoCs

- `0vercl0k/CVE-2021-28476`  -  vmswitch PoC (archived)

---

## 3. KVM / QEMU (12+ CVEs)

### CVEs Críticos

| CVE | CVSS | Tipo | Módulo CXF |
|-----|------|------|------------|
| CVE-2019-14835 | 7.8 | vhost_net buffer overflow (live migration) | `kvm-cve-2019-14835` |
| CVE-2019-18389 | 7.8 | virglrenderer heap overflow (3dRedPill) | `kvm-cve-2019-18389` |
| CVE-2019-14378 | 8.8 | slirp heap overflow | `qemu-slirp-escape` |
| CVE-2020-14364 | 5.0 | USB EHCI OOB | `qemu-cve-2020-14364` |
| CVE-2020-7039 | 5.6 | libslirp OOB | `qemu-slirp-escape` |
| CVE-2023-2680 | 8.2 | DMA reentrancy (virtio-crypto) | `qemu-dma-reentrancy` |
| CVE-2023-3180 | 6.0 | virtio-crypto OOB | `qemu-dma-reentrancy` |
| CVE-2023-3301 | 5.6 | VNC race condition | `qemu-dma-reentrancy` |
| CVE-2023-4135 | 6.0 | NVMe OOB read | `qemu-dma-reentrancy` |
| CVE-2023-6693 | 5.3 | virtio-net OOB | `qemu-cve-2023-6693` |
| CVE-2024-3446 |  -  | virtio-pci | `qemu-cve-2024-3446` |
| CVE-2024-4467 |  -  | QEMU image handling | `qemu-cve-2024-4467` |
| CVE-2024-6519 |  -  | QEMU OOB access | `qemu-cve-2024-6519` |

### GitHub Collections

- `0xbbdd/QEMU-CVEs`  -  curated QEMU CVE list
- `V4bel/Januscape`  -  KVM escape PoCs
- `V4bel/ITScape`  -  KVM/QEMU escape PoCs
- `winmin/awesome-vm-escape`  -  comprehensive VM escape collection

---

## 4. Xen / Citrix Hypervisor (10+ XSAs)

### Xen Security Advisories

| XSA | CVE | Tipo | Módulo CXF |
|-----|-----|------|------------|
| XSA-340 | CVE-2020-29480+ | Event channel escape (privesc) | `xen-grant-escape` |
| XSA-400 | CVE-2022-26358/59/60/61 | IOMMU handling | `xen-iommu-exploit` |
| XSA-486 | CVE-2026-23558 | Guest-to-host compromise | `citrix-xsa-486` |
| XSA-500 | CVE-2026-62428 | Grant-copy type confusion | `xen-xsa500` |
| XSA-501 |  -  | Grant-table version-switching race | `xen-grant-escape` |
| XSA-502 |  -  | vNUMA cleanup race | `xen-xsa505` |
| XSA-505 |  -  | Various | `xen-xsa505` |
| XSA-517 |  -  | Various | `xen-xsa517` |
| XSA-521 |  -  | Various | `xen-xsa521` |
| XSA-148 (classic) | CVE-2015-7835 | PV pagetable escape | `xen-venom` |

### Citrix Hypervisor

| CVE | Tipo | Módulo CXF |
|-----|------|------------|
| CVE-2024-45817 | Host crash via malicious guest admin | N/A (DoS) |
| CVE-2026-23558 (XSA-486) | Privileged guest-to-host | `citrix-xsa-486` |
| CVE-2026-53562 | Citrix escape | `citrix-cve-2026-53562` |

---

## 5. Container Escape CVEs

| CVE | Componente | Tipo | Módulo CXF |
|-----|-----------|------|------------|
| CVE-2019-5736 | runc | /proc/self/exe overwrite | `cve-2019-5736` |
| CVE-2021-30465 | runc | Mount race condition | `cve-2021-30465` |
| CVE-2022-0492 | Linux kernel | cgroup release_agent | `cve-2022-0492` |
| CVE-2022-0847 | Linux kernel | Dirty Pipe container escape | `cve-2022-0847` |
| CVE-2022-23648 | containerd | Volume mount file read | `cve-2022-23648` |
| CVE-2024-21626 | runc (Leaky Vessels) | /proc/self/fd workdir escape | `cve-2024-21626` |
| CVE-2024-23651 | BuildKit | Mount cache race | `cve-2024-23651` |
| CVE-2024-23652 | BuildKit | Arbitrary delete | `cve-2024-23652` |
| CVE-2024-23653 | BuildKit | GRPC privesc | `cve-2024-23653` |
| CVE-2025-31133 | runc | Symlink bind-mount escape | `cve-2025-31133` |
| CVE-2025-52565 | runc | Bind-mount read-write | `cve-2025-52565` |
| CVE-2025-52881 | runc | Incomplete fix 2019-16884 | `cve-2025-52881` |

---

## 6. MicroVM / Sandbox Escape

### Firecracker

| CVE | Tipo | Módulo CXF |
|-----|------|------------|
| CVE-2026-5747 | virtio-pci OOB write | `firecracker-escape` |
| CVE-2026-1386 | Jailer symlink host write | `firecracker-escape` |

### Kata Containers

| CVE | Tipo | Módulo CXF |
|-----|------|------------|
| CVE-2026-44210 | virtiofsd arg injection (source=/) | `kata-escape` |
| CVE-2026-47243 | FUSE host-root via virtio-fs PCI | `kata-escape` |

### gVisor

Nenhum CVE de escape público encontrado. Design de kernel userspace isola syscalls do host.

---

## 7. Cloud Provider Hypervisors

### AWS Nitro

Nenhum CVE de escape público. Design com offload para Nitro Cards. Confirmado não afetado por XSA-336 e L1TF Reloaded.

### Azure Hypervisor

| Módulo CXF | Descrição |
|------------|-----------|
| `azurescape` | ChaosDB / cross-tenant via ACI |
| `fabricscape` | Service Fabric escape |

### GCP

Nenhum CVE de guest-to-host escape público contra o hypervisor GCP.

---

## 8. VDI Escape

| CVE | Produto | Tipo | Módulo CXF |
|-----|---------|------|------------|
| CVE-2020-3961 | VMware Horizon Client | LPE via DLL loading | `vdi-breakout` |
| CVE-2025-6759 | Citrix Virtual Apps | SYSTEM handle leak LPE | `vdi-breakout` |
|  -  | Generic | Kiosk/shell/dialog escape | `vdi-breakout-*` |

---

## 9. Repositórios de Referência

| Repo | Descrição |
|------|-----------|
| `xairy/vmware-exploitation` | VMware exploitation curated list |
| `winmin/awesome-vm-escape` | Comprehensive VM escape collection |
| `0xbbdd/QEMU-CVEs` | QEMU CVE collection |
| `0vercl0k/CVE-2021-28476` | Hyper-V vmswitch PoC |
| `V4bel/Januscape` / `V4bel/ITScape` | KVM escape PoCs |
| `NitroCao/CVE-2024-21626` | runc Leaky Vessels PoC |
| `JlSakuya/CVE-2022-0847-container-escape` | Dirty Pipe container escape |
| `Markakd/Container_escape` | Kernel container escape PoCs |
| `404tk/cloudtoolkit` | Multi-cloud exploitation toolkit |

---

## 10. MITRE ATT&CK Mapping

Técnicas mais frequentes nos módulos virt/k8s/escape:

| Técnica | Nome | Cobertura |
|---------|------|-----------|
| T1611 | Escape to Host | 60+ módulos |
| T1190 | Exploit Public-Facing Application | 25+ módulos |
| T1078 | Valid Accounts | 15+ módulos |
| T1068 | Exploitation for Privilege Escalation | 10+ módulos |
| T1210 | Exploitation of Remote Services | 8+ módulos |
| T1059 | Command and Scripting Interpreter | 8+ módulos |
| T1005 | Data from Local System | 5+ módulos |
| T1486 | Data Encrypted for Impact | 3+ módulos |
