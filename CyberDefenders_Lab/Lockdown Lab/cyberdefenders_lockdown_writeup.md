# CyberDefenders Write-up

**Lab:** Lockdown\
**Platform:** CyberDefenders\
**Category:** Network Forensics\
**Difficulty:** Easy

------------------------------------------------------------------------

# Scenario

TechNova Systems' SOC detected suspicious outbound traffic originating
from a public-facing IIS server hosted in their cloud environment.
Initial indicators suggested that the server may have been compromised
through the deployment of a **web shell followed by command-and-control
communication**.

To investigate the incident, three forensic artifacts were provided:

-   A **PCAP file** containing network traffic
-   A **memory dump** of the compromised system
-   A **malware sample** recovered from disk

The objective of this investigation is to **reconstruct the attacker's
activities**, identify indicators of compromise, and map the observed
behavior to relevant MITRE ATT&CK techniques.

------------------------------------------------------------------------

# PCAP Analysis

## Q1. After flooding the IIS host with rapid-fire probes, the attacker reveals their origin. Which IP address generated this reconnaissance traffic?

### Method

``` bash
tshark -r capture.pcapng -q -z conv,tcp | sort -rn | head -20
```

### Finding

**10.0.2.4**

------------------------------------------------------------------------

## Q2. Zeroing in on a single open service to gain a foothold, the attacker carries out targeted enumeration. Which MITRE ATT&CK technique ID covers this activity?

### Method

Behavior matched MITRE ATT&CK service discovery.

### Finding

**T1046 -- Network Service Discovery**

------------------------------------------------------------------------

## Q3. While reviewing SMB traffic, two Tree Connect requests reveal the first shares the intruder probes on the IIS host. Which UNC paths are accessed?

### Method

``` bash
tshark -r capture.pcapng -Y "smb2.cmd==3" -T fields -e ip.src -e ip.dst -e smb2.tree
```

### Finding

    \\10.0.2.15\Documents
    \\10.0.2.15\IPC$

------------------------------------------------------------------------

## Q4. Inside the share, the attacker uploads a web-accessible payload. What is the filename and its byte length in the SMB2 Write request?

### Method

``` bash
tshark -r capture.pcapng -Y "smb2.cmd==9" -T fields -e ip.src -e smb2.filename -e smb2.write_length
```

### Finding

Filename:

    shell.aspx

Write Length:

    1015024 bytes

------------------------------------------------------------------------

## Q5. The web shell establishes a reverse connection. Which port is used?

### Method

``` bash
tshark -r capture.pcapng -Y "ip.src == 10.0.2.15 && ip.dst == 10.0.2.4" -T fields -e tcp.dstport | sort | uniq -c
```

### Finding

**4443**

------------------------------------------------------------------------

# Memory Analysis

## Q6. What is the kernel base address in the memory dump?

### Method

``` bash
vol -f memdump.mem windows.info
```

### Finding

    0xf80079213000

------------------------------------------------------------------------

## Q7. A suspicious executable indicates persistence. What is its full path and the corresponding MITRE technique?

### Method

``` bash
vol -f memdump.mem windows.pstree
```

### Finding

    C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe

MITRE Technique:

**T1547 -- Boot or Logon Autostart Execution**

------------------------------------------------------------------------

## Q8. Which process handled the reverse shell communication?

### Method

``` bash
vol -f memdump.mem windows.netstat
```

### Finding

Process: **w3wp.exe**\
PID: **4332**

------------------------------------------------------------------------

# Malware Analysis

## Q9. Which packer was used to obfuscate the malware?

### Method

Analysis performed with Detect It Easy (DIE).

### Finding

**UPX**

------------------------------------------------------------------------

## Q10. Which domain does the malware contact for command-and-control?

### Method

Threat intelligence lookup performed on VirusTotal.

### Finding

    cp8nl.hyperhost.ua

------------------------------------------------------------------------

## Q11. Which malware family does the sample belong to?

### Method

Community intelligence from VirusTotal.

### Finding

**AgentTesla**

------------------------------------------------------------------------

# Conclusion

The investigation reconstructed a **multi-stage intrusion** involving
reconnaissance, web shell deployment, persistence establishment, and
command-and-control communication.

The attacker first performed network reconnaissance, then enumerated SMB
shares on the IIS server. A malicious **ASPX web shell** was uploaded to
enable remote command execution. Following the compromise, a
**UPX-packed AgentTesla sample** was deployed, persistence was
established via the **Startup folder**, and communication with a
command-and-control server occurred through a reverse shell.

This case demonstrates how **network traffic analysis, memory forensics,
and malware intelligence** can be combined to reconstruct attacker
activity and identify indicators of compromise.
