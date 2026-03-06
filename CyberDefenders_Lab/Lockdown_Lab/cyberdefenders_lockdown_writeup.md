# CyberDefenders Write-up – Lockdown Lab

| Field | Details |
|-------|---------|
| **Platform** | CyberDefenders |
| **Category** | Network Forensics |
| **Difficulty** | Easy |

---

## Scenario

TechNova Systems' Security Operations Center (SOC) detected suspicious outbound traffic originating from a public-facing IIS server hosted in their cloud infrastructure. Initial alerts suggested that the server may have been compromised and was communicating with an external host.

Three forensic artefacts were provided to investigate the incident:

- A PCAP capture containing network traffic
- A memory dump of the compromised system
- A malware sample recovered from disk

The objective of the investigation is to reconstruct the attacker's activities, identify indicators of compromise, and understand how the attacker gained and maintained access to the system. The investigation combines network traffic analysis, memory forensics, and malware intelligence to build a complete picture of the intrusion.

---

## PCAP Analysis

### Q1. After flooding the IIS host with rapid-fire probes, the attacker reveals their origin. Which IP address generated this reconnaissance traffic?

The first step in the investigation was to identify which host was responsible for the initial reconnaissance activity. Since reconnaissance often involves sending a large number of connection attempts, examining TCP conversations in the capture can help identify the most active communicating hosts.

To do this, I used `tshark` to generate TCP conversation statistics from the PCAP file and sorted the results to highlight the most active connections.

```bash
tshark -r capture.pcapng -q -z conv,tcp | sort -rn | head -20
```

This command extracts TCP conversation statistics and lists the endpoints generating the highest number of packets. By reviewing the output, it became clear that one particular IP address was responsible for a large number of connection attempts targeting the IIS server.

This pattern is consistent with network scanning or reconnaissance activity, where an attacker probes multiple ports or services to identify potential entry points.

> **Answer:** `10.0.2.4`

---

### Q2. Zeroing in on a single open service to gain a foothold, the attacker carries out targeted enumeration. Which MITRE ATT&CK technique ID covers this activity?

After identifying the attacker's IP address, the next step was to classify the activity observed in the network traffic.

The attacker appeared to be probing services on the IIS server to determine which ports or services were accessible. This type of activity aligns with the MITRE ATT&CK framework's **Network Service Discovery** technique.

Within the MITRE ATT&CK framework, this behavior is categorized under:

> **Answer:** `T1046` – Network Service Discovery

This technique describes situations where an attacker scans or probes a target system to identify running services that could be exploited to gain access.

---

### Q3. While reviewing the SMB traffic, you observe two consecutive Tree Connect requests that expose the first shares the intruder probes on the IIS host. Which two full UNC paths are accessed?

Once a potential target service was identified, the attacker began interacting with the system using the SMB protocol. SMB is commonly used in Windows environments for file and resource sharing.

To identify which SMB shares were accessed, I filtered the capture for SMB2 Tree Connect requests, which occur when a client attempts to access a specific share on a server.

```bash
tshark -r capture.pcapng -Y "smb2.cmd==3" -T fields -e ip.src -e ip.dst -e smb2.tree
```

The `smb2.cmd==3` filter isolates Tree Connect requests, which reveal the share paths being accessed. Reviewing the results showed two early share access attempts by the attacker:

> **Answer:**
> ```
> \\10.0.2.15\Documents
> \\10.0.2.15\IPC$
> ```

The first is a regular shared folder, while `IPC$` is a special administrative share often used for inter-process communication. These accesses indicate that the attacker was enumerating available SMB shares to locate writable locations.

---

### Q4. Inside the share, the attacker plants a web-accessible payload that will grant remote code execution. What is the filename of the malicious file they uploaded, and what byte length is specified in the corresponding SMB2 Write Request?

After accessing the SMB share, the attacker uploaded a file to the system. To identify this activity, I filtered the capture for SMB2 Write requests, which occur when data is written to a file on the server.

```bash
tshark -r capture.pcapng -Y "smb2.cmd==9" -T fields -e ip.src -e smb2.filename -e smb2.write_length
```

Among the results was a suspicious file upload involving an `.aspx` file. ASPX files are executable web scripts used by Microsoft IIS servers. Uploading such a file often indicates the deployment of a **web shell**, which allows an attacker to execute commands remotely through a web interface.

> **Answer:**
> - **Filename:** `shell.aspx`
> - **Write Length:** `1015024` bytes

---

### Q5. The newly planted shell calls back to the attacker over an uncommon but firewall-friendly port. Which listening port did the attacker use for the reverse shell?

Once the web shell was deployed, the attacker used it to establish a reverse shell connection back to their system. Reverse shells allow compromised systems to initiate outbound connections to an attacker-controlled host, often bypassing firewall restrictions.

To identify the port used for this communication, I filtered for traffic originating from the compromised server (`10.0.2.15`) and destined for the attacker's machine (`10.0.2.4`).

```bash
tshark -r capture.pcapng -Y "ip.src == 10.0.2.15 && ip.dst == 10.0.2.4" -T fields -e tcp.dstport | sort | uniq -c
```

By aggregating destination ports used in these communications, one port stood out as being repeatedly used. This port resembles HTTPS (443), which may help disguise malicious traffic as legitimate encrypted communication.

> **Answer:** `4443`

---

## Memory Dump Analysis

### Q6. Your memory snapshot captures the system’s kernel in situ, providing vital context for the breach. What is the kernel base address in the dump?

The next phase of the investigation involved analyzing the memory dump of the compromised server. Using Volatility3, the `windows.info` plugin was executed to gather system-level information from the memory image.

```bash
vol -f memdump.mem windows.info
```

> **Answer:** `0xf80079213000`

---

### Q7. A trusted service launches an unfamiliar executable residing outside the usual IIS stack, signalling a persistence implant. What is the final full on-disk path of that executable, and which MITRE ATT&CK persistence technique ID corresponds to this behaviour?

To identify suspicious processes and their parent-child relationships, I examined the process tree using the following Volatility plugin:

```bash
vol -f memdump.mem windows.pstree
```

Reviewing the process tree revealed a suspicious executable located within the **Startup folder**, which is commonly used to automatically launch programs when a user logs in. Placing malware in this directory ensures that it runs whenever the system starts or a user logs in.

> **Answer:**
> - **Path:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe`
> - **MITRE ATT&CK:** `T1547` – Boot or Logon Autostart Execution

---

### Q8. The reverse shell’s outbound traffic is handled by a built-in Windows process that also spawns the implanted executable. What is the name of this process, and what PID does it run under?

To determine which process handled the outbound communication associated with the reverse shell, I examined active network connections present in memory.

```bash
vol -f memdump.mem windows.netstat
```

The output revealed that the network connection associated with the attacker's IP address was linked to the IIS worker process. Since the web shell was deployed through the IIS environment, it is logical that the reverse shell activity would originate from this process.

> **Answer:**
> - **Process:** `w3wp.exe`
> - **PID:** `4332`

---

## Malware Analysis

### Q9. Static inspection reveals the binary has been packed to hinder analysis. Which packer was used to obfuscate it?

To perform initial static analysis on the recovered malware sample, I used **Detect It Easy (DIE)**. The tool indicated that the binary had been packed using a common executable packer that compresses binaries and can obscure the original code structure, making analysis more difficult.

> **Answer:** `UPX`

---

### Q10. Threat-intel analysis shows the malware beaconing to its command-and-control host. Which fully qualified domain name (FQDN) does it contact?

To identify potential command-and-control infrastructure used by the malware, I submitted the file hash to **VirusTotal**. Reviewing the **Relations** section revealed the domain the sample communicated with.

> **Answer:** `cp8nl.hyperhost.ua`

---

### Q11. Open-source intel associates that hash with a well-known commodity RAT. To which malware family does the sample belong?

Further analysis of the VirusTotal report revealed that the malware sample had already been analyzed and classified by the security community.

> **Answer:** `AgentTesla` – a well-known commodity Remote Access Trojan (RAT) commonly used for credential theft and remote system control.

---

## Conclusion

This investigation reconstructed a multi-stage compromise of an IIS server using a combination of network, memory, and malware analysis. The attack followed a typical intrusion pattern:

| Stage | Activity |
|-------|----------|
| **1. Reconnaissance** | Network scanning to identify accessible services (`T1046`) |
| **2. Enumeration** | SMB share enumeration to locate writable locations |
| **3. Initial Access** | Upload of `shell.aspx` web shell via SMB |
| **4. Execution** | Reverse shell established on port `4443` via `w3wp.exe` |
| **5. Persistence** | Malicious executable placed in Windows Startup folder (`T1547`) |
| **6. C2** | UPX-packed AgentTesla RAT communicating with `cp8nl.hyperhost.ua` |

By correlating artifacts across network traffic, memory structures, and malware intelligence, it was possible to reconstruct the full attack chain and identify key indicators of compromise.
