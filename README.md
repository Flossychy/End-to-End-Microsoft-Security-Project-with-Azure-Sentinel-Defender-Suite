#  Hybrid Enterprise Security Lab — Microsoft Defender XDR + Sentinel

> A fully functional hybrid security operations environment built on Azure, integrating Microsoft Defender XDR (Endpoint, Identity, Cloud Apps) with Microsoft Sentinel as the central SIEM/SOAR platform. Designed to mirror real-world enterprise detection and response workflows across cloud and on-premises infrastructure.



##  Table of Contents

- [Project Summary](#-project-summary)
- [Architecture](#-architecture)
- [Infrastructure Topology](#-infrastructure-topology)
- [Deployment Walkthrough](#-deployment-walkthrough)
  - [1. Azure Resource Group & Networking](#1-azure-resource-group--networking)
  - [2. Domain Controller Setup](#2-domain-controller-setup)
  - [3. gMSA & Directory Service Account](#3-gmsa--directory-service-account)
  - [4. Windows VMs — Domain Join](#4-windows-vms--domain-join)
  - [5. Ubuntu Linux VM — AD Integration](#5-ubuntu-linux-vm--ad-integration)
  - [6. VNet Peering](#6-vnet-peering)
  - [7. Defender for Endpoint Onboarding](#7-defender-for-endpoint-onboarding)
  - [8. Defender for Identity — Sensor Deployment](#8-defender-for-identity--sensor-deployment)
  - [9. Defender for Cloud Apps — App Governance](#9-defender-for-cloud-apps--app-governance)
  - [10. Microsoft Sentinel — SIEM Configuration](#10-microsoft-sentinel--siem-configuration)
  - [11. Threat Detection with KQL](#11-threat-detection-with-kql)
  - [12. SOAR — Automated Response Playbooks](#12-soar--automated-response-playbooks)
- [Challenges & Engineering Decisions](#-challenges--engineering-decisions)
- [Outcomes](#-outcomes)
- [Next Steps](#-next-steps)
- [Tech Stack](#-tech-stack)



##  Project Summary

This project builds a **hybrid enterprise security monitoring lab** that simulates the architecture and operational demands of a real corporate SOC environment. The lab spans on-premises Active Directory, cloud-hosted virtual machines across segmented Azure VNets, and Microsoft's full Defender XDR suite — all feeding into **Microsoft Sentinel** for centralized detection, investigation, and automated response.

The work covers identity management, cross-platform endpoint onboarding, cloud application governance, log ingestion pipeline configuration, KQL-based analytics rule authoring, and SOAR playbook automation — end to end.



##  Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Azure Subscription                     │
│                                                               │
│   ┌──────────────┐    ┌──────────────┐    ┌───────────────┐  │
│   │  VNet-DC      │    │ VNet-Windows │    │  VNet-Linux   │  │
│   │ 10.0.0.0/16  │◄──►│ 10.1.0.0/16 │◄──►│ 10.2.0.0/16  │  │
│   │              │    │              │    │               │  │
│   │  DC-VM        │    │  Win-VM3     │    │  Lin-VM       │  │
│   │  Win-VM1      │    │              │    │  (Ubuntu)     │  │
│   │  Win-VM2      │    │              │    │               │  │
│   └──────┬───────┘    └──────────────┘    └───────────────┘  │
│          │                                                    │
│   ┌──────▼──────────────────────────────────────────────┐    │
│   │           Log Analytics Workspace                    │    │
│   │                                                      │    │
│   │   Defender for Endpoint  │  Defender for Identity   │    │
│   │   Defender for Cloud Apps│  Windows Security Events │    │
│   └──────────────────────────┬───────────────────────────┘    │
│                              │                                │
│                    ┌─────────▼──────────┐                    │
│                    │  Microsoft Sentinel │                    │
│                    │  (SIEM + SOAR)      │                    │
│                    └────────────────────┘                    │
└──────────────────────────────────────────────────────────────┘
```



##  Infrastructure Topology

| VM Name   | OS                | Role                          | VNet         |
|-----------|-------------------|-------------------------------|--------------|
| DC-VM     | Windows Server    | Active Directory DC + Defender Identity Sensor | VNet-DC |
| Win-VM1   | Windows 11        | Domain client, Defender for Endpoint enrolled  | VNet-DC |
| Win-VM2   | Windows 11        | Domain client, Defender for Endpoint enrolled  | VNet-DC |
| Win-VM3   | Windows 11        | Isolated domain client (cross-VNet)            | VNet-Windows |
| Lin-VM    | Ubuntu 22.04 LTS  | Linux endpoint, AD-joined via realmd/SSSD      | VNet-Linux   |

All VMs reside under a single **Azure Resource Group** with shared Network Security Groups and a centralised **Log Analytics Workspace** feeding into Sentinel.



##  Deployment Walkthrough

### 1. Azure Resource Group & Networking

All resources were deployed into a single Resource Group for unified governance and cost tracking.

**VNet Configuration:**

| VNet          | Address Space  | Subnet          | Purpose                        |
|---------------|---------------|-----------------|--------------------------------|
| VNet-DC       | 10.0.0.0/16   | 10.0.0.0/24     | Domain Controller + 2 clients  |
| VNet-Windows  | 10.1.0.0/16   | 10.1.0.0/24     | Isolated Windows client        |
| VNet-Linux    | 10.2.0.0/16   | 10.2.0.0/24     | Ubuntu syslog/endpoint         |

Network Security Groups were applied per subnet with rules permitting RDP/SSH for management and domain traffic (Kerberos TCP/UDP 88, LDAP 389, DNS 53) across peered networks.



### 2. Domain Controller Setup

A Windows Server VM was promoted to an **Active Directory Domain Controller** to serve as the identity backbone for the entire lab.

**AD DS Installation:**

```powershell
# Install AD Domain Services role
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promote server to Domain Controller and create the forest
Install-ADDSForest `
  -DomainName "controller.local" `
  -DomainNetbiosName "CONTROLLER" `
  -ForestMode "WinThreshold" `
  -DomainMode "WinThreshold" `
  -InstallDns:$true `
  -Force:$true
```

After promotion and restart, Organizational Units (OUs), security groups, and user accounts were created to mirror a structured enterprise directory:

```powershell
# Create OUs
New-ADOrganizationalUnit -Name "Workstations" -Path "DC=controller,DC=local"
New-ADOrganizationalUnit -Name "Servers"      -Path "DC=controller,DC=local"
New-ADOrganizationalUnit -Name "ServiceAccounts" -Path "DC=controller,DC=local"

# Create a sample domain user
New-ADUser `
  -Name "John Doe" `
  -GivenName "John" `
  -Surname "Doe" `
  -SamAccountName "jdoe" `
  -UserPrincipalName "jdoe@controller.local" `
  -AccountPassword (ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force) `
  -Enabled $true `
  -Path "OU=Workstations,DC=controller,DC=local"
```



### 3. gMSA & Directory Service Account

A **Group Managed Service Account (gMSA)** was configured to allow Defender for Identity to securely query Active Directory without using a standard credential that could be stolen or expire.

```powershell
# Variables
$gmsaName  = "DC-MSA2"
$groupName = "gmsa-server"
$dcAccount = $env:COMPUTERNAME + "$"

# Create a security group to control which machines can retrieve the gMSA password
if (-not (Get-ADGroup -Filter { Name -eq $groupName })) {
    New-ADGroup `
      -Name $groupName `
      -GroupScope Global `
      -Path "OU=ServiceAccounts,DC=controller,DC=local"
}

# Create the gMSA, scoped to the domain controller DNS name
if (-not (Get-ADServiceAccount -Filter { Name -eq $gmsaName })) {
    New-ADServiceAccount `
      -Name $gmsaName `
      -DNSHostName "$gmsaName.controller.local" `
      -PrincipalsAllowedToRetrieveManagedPassword $groupName
}

# Add DC machine account to the retrieval group
Add-ADGroupMember -Identity $groupName -Members $dcAccount

# Install and verify gMSA on the DC
Install-ADServiceAccount -Identity $gmsaName
Test-ADServiceAccount    -Identity $gmsaName
```

> **Why gMSA?** Standard service accounts introduce credential hygiene risks. gMSAs rotate their own passwords automatically (every 30 days by default), are non-interactive, and cannot be used to log in interactively — a key principle of least-privilege identity design.



### 4. Windows VMs — Domain Join

All Windows VMs were domain-joined to `controller.local`. For the two VMs inside VNet-DC, DNS was pre-configured to point to the Domain Controller's private IP. For Win-VM3 (cross-VNet), DNS was set after VNet peering was established.

**Via PowerShell (preferred for repeatability):**

```powershell
$domainName = "controller.local"
$credential = Get-Credential  # Domain Administrator credentials

Add-Computer `
  -DomainName $domainName `
  -Credential $credential `
  -OUPath "OU=Workstations,DC=controller,DC=local" `
  -Restart
```

**Verification post-restart:**

```powershell
# Confirm domain membership
(Get-WmiObject Win32_ComputerSystem).Domain
# Expected output: controller.local
```

Login using `CONTROLLER\username` confirmed successful domain authentication on all machines.



### 5. Ubuntu Linux VM — AD Integration

Integrating a Linux endpoint into an Active Directory domain requires bridging Kerberos-based authentication with Linux PAM/SSSD. The following was done on the Ubuntu VM.

**Pre-requisite: Point DNS to the Domain Controller**

```bash
sudo nano /etc/resolv.conf
# Add:
nameserver <DC_Private_IP>
search controller.local
```

**Install required packages:**

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
  realmd \
  sssd \
  sssd-tools \
  adcli \
  krb5-user \
  samba-common-bin \
  packagekit
```

> During `krb5-user` installation, set the default realm to `CONTROLLER.LOCAL` (uppercase).

**Discover and join the domain:**

```bash
# Confirm domain is reachable
realm discover controller.local

# Join domain using Domain Administrator account
sudo realm join --user=Azureuser controller.local

# Verify successful domain join
realm list
```

Expected `realm list` output confirms domain membership, configured login format, and SSSD as the provider.

**Enable home directory creation on first login:**

```bash
sudo bash -c "echo 'session required pam_mkhomedir.so skel=/etc/skel/ umask=077' >> /etc/pam.d/common-session"
```

**Test AD login on Linux:**

```bash
su - jdoe@controller.local
# or via SSH:
ssh jdoe@controller.local@<LinuxVM_IP>
```



### 6. VNet Peering

To allow Win-VM3 and Lin-VM (deployed in separate VNets) to communicate with the Domain Controller, bidirectional VNet peering was configured in Azure.

**Peering settings applied:**

- Allow traffic forwarded from remote VNet: ✅ Enabled
- Allow gateway transit: ✅ Enabled (on VNet-DC side)
- Use remote gateways: ✅ Enabled (on VNet-Windows and VNet-Linux sides)

This ensured Kerberos ticket exchange, LDAP queries, and DNS resolution all worked correctly across VNets without requiring a VPN gateway or public IP exposure.



### 7. Defender for Endpoint Onboarding

All Windows and Linux VMs were onboarded to **Microsoft Defender for Endpoint** via Group Policy to ensure automatic coverage of any future domain-joined machines.

**Windows — GPO-Based Onboarding:**

1. Downloaded the onboarding package from:  
   `Microsoft Defender Portal → Settings → Endpoints → Device Management → Onboarding`
2. Extracted the package and placed the `.cmd` script in a GPO-accessible network share.
3. Created a new GPO linked to the `Workstations` OU:
   - `Computer Configuration → Preferences → Windows Settings → Files` — to copy the package
   - `Computer Configuration → Preferences → Windows Settings → Scheduled Tasks` — to execute it silently on first boot

**Linux — Manual Onboarding via Microsoft Script:**

```bash
# Download onboarding script from Defender portal
# Run the onboarding script
sudo python3 MicrosoftDefenderATPOnboardingLinuxServer.py

# Verify MDE is running
mdatp health
```

Onboarded devices appeared in the **Microsoft Defender Portal → Device Inventory** within 5–10 minutes.



### 8. Defender for Identity — Sensor Deployment

Defender for Identity monitors Active Directory for identity-based attacks such as Pass-the-Hash, Kerberoasting, lateral movement, and DCSync attacks.

**Sensor installation on the Domain Controller:**

1. Logged into `security.microsoft.com`
2. Navigated to `Settings → Identities → Sensors → Add Sensor`
3. Copied the **Access Key** from the portal
4. Transferred the installer to the DC and ran it:
   - Sensor type: **Domain Controller**
   - Pasted the Access Key when prompted
5. The sensor began syncing AD activity to the Defender XDR portal within minutes

**Verify sensor health:**

In the Defender portal under `Settings → Identities → Sensors`, the DC should show as **Running** with no configuration errors.

The gMSA created in Step 3 (`DC-MSA2`) was configured as the **Directory Service Account**, granting Defender for Identity read-only access to AD without exposing privileged credentials.



### 9. Defender for Cloud Apps — App Governance

Cloud App governance was configured to monitor and control access to unsanctioned and risky applications across the enterprise.

**Objective:** Detect and block access to **ChatGPT** and **Windscribe VPN** — two high-risk applications identified for policy enforcement.

**Steps:**

1. Navigated to `Microsoft Defender Portal → Cloud Apps → Policies → App Discovery`
2. Created a **Custom Indicator** policy for each application
3. Used wildcard domain format in the indicators:

```
*.chatgpt.com
*.openai.com
*.windscribe.com
*.windscribevpn.com
```

>  **Lesson learned:** Initial attempts used bare domain entries (e.g., `chatgpt.com`) which caused inconsistent blocking. Switching to wildcard format (`*.chatgpt.com`) resolved this, catching all subdomains used by the applications.

**Enforcement scope:**  
Initial testing showed blocking only worked in **Microsoft Edge** because Defender for Cloud Apps enforcement natively integrates with Edge. To extend coverage to Chrome and Firefox:

- Enabled **Network Protection** in Defender for Endpoint (`Audit → Block` mode)
- This extended indicator enforcement at the network layer across all browsers



### 10. Microsoft Sentinel — SIEM Configuration

Microsoft Sentinel was configured as the centralised platform for log aggregation, analytics, alerting, and automated response.

**Setup:**

1. Created a **Log Analytics Workspace** in the same Resource Group
2. Enabled Microsoft Sentinel on top of the workspace
3. Connected all data sources via the **Data Connectors** blade

**Data Connectors enabled:**

| Connector                        | Log Types Ingested                            |
|----------------------------------|-----------------------------------------------|
| Microsoft Defender for Endpoint  | Device events, alerts, process/file telemetry |
| Microsoft Defender for Identity  | Identity alerts, AD activity                  |
| Microsoft Defender for Cloud Apps| App discovery, policy violations              |
| Windows Security Events (via AMA)| Event IDs 4625, 4648, 4768, 4776, 4740       |

**Analytics Rules created:**

| Rule Name                          | Trigger Condition                                        | Severity |
|------------------------------------|----------------------------------------------------------|----------|
| Brute Force — Failed Logins        | >10 failed logins (Event 4625) in 5 min from same host  | High     |
| Suspicious Lateral Movement        | Auth attempts across multiple hosts in short timeframe  | High     |
| Risky App Usage Detected           | Cloud Apps alert for ChatGPT / Windscribe               | Medium   |
| New Local Admin Account Created    | Event 4732 — user added to Administrators group         | Medium   |
| Service Account Used Interactively | gMSA or service account triggers interactive logon      | High     |



### 11. Threat Detection with KQL

Custom KQL queries were authored to support threat hunting and feed analytics rules.

**Brute Force / Credential Stuffing — Failed Logins:**

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count() by Account, Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
| order by FailedAttempts desc
```

**Lateral Movement — Authentication Across Multiple Hosts:**

```kql
SecurityEvent
| where EventID == 4648  // Explicit credential logon
| where TimeGenerated > ago(30m)
| summarize TargetHosts = dcount(Computer), AttemptCount = count() by Account, IpAddress
| where TargetHosts > 2
| project Account, IpAddress, TargetHosts, AttemptCount
```

**Account Lockouts:**

```kql
SecurityEvent
| where EventID == 4740
| summarize LockoutCount = count() by TargetAccount, Computer, TimeGenerated
| order by LockoutCount desc
```

**Defender Alerts — High Severity Triage:**

```kql
SecurityAlert
| where AlertSeverity == "High"
| where TimeGenerated > ago(24h)
| project TimeGenerated, AlertName, CompromisedEntity, Description, Entities
| order by TimeGenerated desc
```



### 12. SOAR — Automated Response Playbooks

Logic App-based playbooks were built in Sentinel to automate initial incident response actions.

**Playbook: Auto-Isolate Endpoint on High-Severity Alert**

Trigger: Sentinel incident with severity = High + entity type = Host  
Actions:
1. Extract device name from incident entities
2. Call **Defender for Endpoint API** → `Isolate Machine` action
3. Post notification to Teams channel with incident details and isolation status
4. Add comment to Sentinel incident: `"Host isolated automatically — awaiting analyst review"`

**Playbook: Disable AD User on Identity Alert**

Trigger: Defender for Identity alert — Pass-the-Hash or credential theft  
Actions:
1. Extract `AccountName` from alert entities
2. Call **Microsoft Graph API** → Disable user account in Entra ID
3. Force sign-out of all active sessions
4. Log action in Sentinel incident timeline



##  Challenges & Engineering Decisions

| Challenge | Root Cause | Resolution |
|-----------|-----------|------------|
| Ubuntu VM failed to join AD | Missing `realmd`/`sssd` packages + DNS not pointing to DC | Installed all dependencies, updated `/etc/resolv.conf` to DC IP before joining |
| Cloud App blocking only worked in Edge | Defender for Cloud Apps enforces natively in Edge only | Extended enforcement to all browsers via Defender for Endpoint Network Protection |
| Sentinel not receiving Windows logs | Log Analytics agent not configured; AMA connector not enabled | Deployed Azure Monitor Agent via GPO; configured Windows Security Events connector in Sentinel |
| gMSA configuration failed | DC machine account not added to the gMSA retrieval security group | Added `$env:COMPUTERNAME$` to the `gmsa-server` group before running `Test-ADServiceAccount` |
| VMs in separate VNets couldn't reach DC | No routing between VNet-Windows/VNet-Linux and VNet-DC | Configured bidirectional VNet peering with gateway transit enabled |
| Wildcard indicator blocking inconsistent | Bare domain entries missed subdomains used by target apps | Switched all custom indicators to wildcard format (`*.domain.com`) |



##  Outcomes

- **Unified visibility** across 5 virtual machines spanning 3 Azure VNets — both Windows and Linux endpoints reporting to a single Sentinel workspace
- **Identity threat monitoring** active on the domain controller via Defender for Identity, with gMSA-backed service account access
- **Application governance** enforced across all browsers using Defender for Endpoint Network Protection as the enforcement layer
- **15+ Sentinel analytics rules** deployed, covering brute force, lateral movement, privilege escalation, and shadow IT
- **Automated incident response** via Logic App playbooks — endpoints isolated and accounts disabled without manual intervention
- **KQL threat hunting** capability demonstrated across authentication, network, and endpoint telemetry



##  Next Steps

- Map all analytics rules to **MITRE ATT&CK** tactics and techniques for structured coverage reporting
- Deploy **Microsoft Entra Conditional Access** policies to enforce MFA and device compliance as Zero Trust controls
- Build a **Sentinel Workbook** dashboard for SOC-style incident triage and metrics visualisation
- Expand Linux coverage with **Syslog + CEF connectors** to ingest auditd and authentication logs from Lin-VM



##  Tech Stack

| Category              | Technology                                      |
|-----------------------|-------------------------------------------------|
| Cloud Platform        | Microsoft Azure                                 |
| SIEM / SOAR           | Microsoft Sentinel + Logic Apps                 |
| Endpoint Security     | Microsoft Defender for Endpoint                 |
| Identity Security     | Microsoft Defender for Identity                 |
| Cloud App Security    | Microsoft Defender for Cloud Apps               |
| Identity Provider     | Active Directory Domain Services + Microsoft Entra ID |
| Operating Systems     | Windows Server 2022, Windows 11, Ubuntu 22.04   |
| Scripting             | PowerShell, Bash                                |
| Query Language        | Kusto Query Language (KQL)                      |
| Networking            | Azure VNet, VNet Peering, NSGs                  |
| Monitoring            | Log Analytics Workspace, Azure Monitor Agent    |



> **Author:** *Florence Nwizugbe*  
> **LinkedIn:** *https://www.linkedin.com/in/florence-nwizugbe/*  
> **Domain:** Cybersecurity | Cloud Security | Identity & Access Management | Security Operations

