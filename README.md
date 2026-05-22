# AWS Support Scripts

Scripts and guides for day-to-day AWS environment management.

@cryptobr on Telegram

---

## 🔐 AWS Security Study Guides

9 guias de estudo sobre Segurança AWS — do GuardDuty ao Threat Modeling:

| # | Guia |
|---|------|
| S01 | [GuardDuty — finding types + multi-conta](estudos_sec/Guia%20S01%20%E2%80%94%20GuardDuty%20em%20profundidade%3A%20finding%20types%20%2B%20multi-conta.md) |
| S02 | [Security Hub — ASFF + cross-conta + EventBridge](estudos_sec/Guia%20S02%20%E2%80%94%20Security%20Hub%3A%20ASFF%20%2B%20agrega%C3%A7%C3%A3o%20cross-conta%20%2B%20EventBridge.md) |
| S03 | [Segurança ofensiva — escalação de privilégios IAM](estudos_sec/Guia%20S03%20%E2%80%94%20Seguran%C3%A7a%20ofensiva%3A%20escala%C3%A7%C3%A3o%20de%20privil%C3%A9gios%20IAM.md) |
| S04 | [Inspector v2 — scanning agentless + ECR + Lambda](estudos_sec/Guia%20S04%20%E2%80%94%20Amazon%20Inspector%20v2%3A%20scanning%20agentless%20%2B%20ECR%20%2B%20Lambda.md) |
| S05 | [AWS Config + Conformance Packs](estudos_sec/Guia%20S05%20%E2%80%94%20AWS%20Config%20%2B%20Conformance%20Packs%3A%20Custom%20Rule%20%2B%20Remediation%20Autom%C3%A1tica.md) |
| S06 | [Exfiltração via S3 + flaws2.cloud](estudos_sec/Guia%20S06%20%E2%80%94%20Seguran%C3%A7a%20Ofensiva%3A%20Exfiltra%C3%A7%C3%A3o%20via%20S3%20%2B%20flaws2.cloud.md) |
| S07 | [CloudTrail — Organization Trail + Log Integrity + Lake SQL](estudos_sec/Guia%20S07%20%E2%80%94%20CloudTrail%20Avan%C3%A7ado%3A%20Organization%20Trail%2C%20Log%20Integrity%20e%20Lake%20SQL.md) |
| S08 | [Amazon Macie — Sensitive Data Discovery](estudos_sec/Guia%20S08%20%E2%80%94%20Amazon%20Macie%3A%20Sensitive%20Data%20Discovery%20%2B%20Suppression%20Rules.md) |
| S09 | [Threat Modeling — STRIDE + IAM Lateral Movement](estudos_sec/Guia%20S09%20%E2%80%94%20Threat%20Modeling%20em%20Workloads%20AWS%3A%20STRIDE%20%2B%20IAM%20Lateral%20Movement.md) |

---

## 🖥️ EC2 & Networking

- **OpenVPN Server (Amazon Linux 2 / 2023):** [readme.md](EC2_OpenVPN_Server/readme.md)
- **OpenVPN Server (Ubuntu 24.04):** [configure_server_ubuntu24.sh](EC2_OpenVPN_Server/configure_server_ubuntu24.sh)
- **Resize Linux Partition:** [resize_linux_partition.sh](Resize_Linux_partition/resize_linux_partition.sh) | [AWS Docs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/recognize-expanded-volume-linux.html)

---

## 🗄️ Storage & Database

- **S3 Bucket Permission (JSON):** [S3ResourcePermission.json](S3ResourcePermission.json)
- **DynamoDB — get with filter:** [getValueWithFilter.py](dynamoDB/getValueWithFilter.py)
- **Install PostgreSQL 16 on Amazon Linux 2023:** [install_psql16_amz_linux_2023.MD](setup/install_psql16_amz_linux_2023.MD)

---

## 🔑 AWS Systems Manager

- **SSH Session (aws-cli):** [ssh_access.md](ssm/ssh_access.md)
- **RDP Session:** [rdp_access.md](ssm/rdp_access.md)
- **RDS Session (aws-cli):** [rds_access.md](ssm/rds_access.md)

---

## 📋 AWS CLI

- **Basic commands:** [aws-cli-commands.md](aws-cli-commands.md)
