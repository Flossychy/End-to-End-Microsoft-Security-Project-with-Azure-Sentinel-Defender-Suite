# End to End Microsoft Security Project with Microsoft Defender XDR
This project demonstrates a complete enterprise security monitoring and protection setup using Microsoft Security tools on Azure.

##  Overview  
This project integrates multiple Microsoft security solutions to simulate a **real-world hybrid enterprise environment**. The lab demonstrates how cloud and on-premises resources can be **protected, monitored, and centrally managed** using Microsoft’s security ecosystem.  

---

##  Integrated Solutions  
- **Microsoft Sentinel** – SIEM & SOAR for centralized monitoring, detection, and automated response.  
- **Microsoft Defender for Cloud Apps** – app visibility, control, and shadow IT detection.  
- **Microsoft Defender for Endpoint** – endpoint detection & response (EDR) for Windows and Linux machines.  
- **Microsoft Defender for Identity** – Active Directory identity monitoring to detect compromised accounts and insider threats.  
- **Microsoft Entra ID** – cloud-based identity and access management for users and applications.  
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

