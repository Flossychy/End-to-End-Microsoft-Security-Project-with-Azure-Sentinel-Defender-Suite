# End-to-End-Microsoft-Security-Project-with-Azure-Sentinel-Defender-Suite
This project demonstrates a complete enterprise security monitoring and protection setup using Microsoft Security tools on Azure.

##  Overview  
This project integrates multiple Microsoft security solutions to simulate a **real-world hybrid enterprise environment**. The lab demonstrates how cloud and on-premises resources can be **protected, monitored, and centrally managed** using Microsoft’s security ecosystem.  

---

##  Integrated Solutions  
- **Microsoft Sentinel** – SIEM & SOAR for centralized monitoring, detection, and automated response.  
- **Microsoft Defender for Cloud Apps** – app visibility, control, and shadow IT detection.  
- **Microsoft Defender for Endpoint** – endpoint detection & response (EDR) for Windows and Linux machines.  
- **Microsoft Defender for Identity** – Active Directory identity monitoring to detect compromised accounts and insider threats.  
- **Azure Active Directory (Entra ID)** – cloud-based identity and access management for users and applications.  
- **On-Premises Domain Controller (Windows Server 2022)** – for Active Directory authentication and GPO management.  
- **Ubuntu Linux VM** – integrated into the domain to test cross-platform security visibility.  
---

## 🎯 Project Goal  
The goal of this project was to **simulate a modern hybrid infrastructure** and showcase how Microsoft’s security stack can:  
1. Detect and respond to threats across endpoints, identities, and applications.  
2. Provide visibility into both **on-premises and cloud environments**.  
3. Centralize monitoring and incident response in Microsoft Sentinel.  

---

## 🛠️ Project Setup  

### **1. Azure Resources**
- Created an **Azure tenant** with Entra ID (Azure AD).  
- Deployed a **Log Analytics Workspace** (for Sentinel & Defender logs).  
- Deployed a **Windows Server 2022 VM** to act as the **Domain Controller**.  
- Deployed an **Ubuntu Linux VM and Windows two Windows 10 and Windows 11** to join the on-premises Active Directory domain.
- Deployed **VNet 1** for the server and the two windows 10, **VNet 2** for windows 11 and **VNet 3** for the linux VM.

---

### **2. Domain Controller (Windows Server 2022)**
- Installed **Active Directory Domain Services (AD DS)**.  
- Promoted the server to a **Domain Controller**.  
- Created **OU structures, user accounts, and security groups**.  
- Configured **Group Managed Service Account (gMSA)** for secure service authentication.  

**PowerShell (Domain Controller setup & gMSA):**
```powershell
# Variables
$gmsaName = "DC-MSA2"
$groupName = "gmsa-server"
$dcName = $env:COMPUTERNAME + "$"

# Create Security Group
if (-not (Get-ADGroup -Filter { Name -eq $groupName })) {
    New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security
}

# Create gMSA
New-ADServiceAccount -Name $gmsaName -DNSHostName "$dcName.$((Get-ADDomain).DNSRoot)" -PrincipalsAllowedToRetrieveManagedPassword $groupName

# Add DC to group
Add-ADGroupMember -Identity $groupName -Members $dcName

3. Ubuntu Linux VM – Join to Active Directory

Installed required packages and joined the Linux VM to the Windows AD domain.

Ubuntu Commands:

# Update and install required packages
sudo apt update && sudo apt upgrade -y
sudo apt install realmd sssd sssd-tools adcli krb5-user samba-common-bin -y

# Discover the domain
realm discover yourdomain.com

# Join the domain
sudo realm join --user=Administrator yourdomain.com

# Verify domain membership
realm list

4. Microsoft Defender Integrations

Defender for Endpoint

Onboarded both Windows & Linux VMs.

Verified alerts appeared in the Security Portal.

Defender for Identity

Installed sensor on Domain Controller.

Synced signals to Microsoft 365 Defender.

Defender for Cloud Apps

Configured App Discovery policies.

Added custom indicators to block/monitor apps like ChatGPT & Windscribe.

5. Microsoft Sentinel

Connected Log Analytics Workspace to Sentinel.

Integrated logs from:

Defender for Endpoint

Defender for Identity

Defender for Cloud Apps

Domain Controller security logs

Built analytics rules to detect suspicious activity (failed logins, lateral movement, etc.).

Created playbooks (SOAR) for automated response actions.

⚡ Roadblocks & Fixes
Issue	Root Cause	Fix
Browsers blocked after Cloud App custom indicators	Incorrect domain entries in indicators	Corrected wildcard domain format (*.example.com)
Ubuntu join failed	Missing packages & wrong realm config	Installed realmd & verified DNS resolution before joining
Sentinel not receiving logs	Log Analytics workspace not linked	Connected Sentinel to existing workspace
Blocking worked only in Edge	Defender for Cloud Apps controls not enforced across browsers	Enforced via network protection & endpoint integration
📜 Key Scripts Used

PowerShell – gMSA & Group Creation

Ubuntu – Domain Join & Realm Config

Sentinel – KQL Queries (example)

SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by Account, Computer, TimeGenerated
| order by FailedLogins desc

✅ Outcomes

Successfully simulated a hybrid enterprise security environment.

Achieved visibility across on-prem & cloud identities, endpoints, and applications.

Built a foundation for incident detection, investigation, and automated response using Sentinel.
