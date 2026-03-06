# CyberDefenders Write-up – CyberStrike

| Field | Details |
|-------|---------|
| **Platform** | CyberDefenders |
| **Category** | Network Forensics |
| **Difficulty** | Easy |

---

## Scenario

A compromised machine was flagged due to suspicious outbound network traffic. The objective of this investigation was to analyze a PCAP file to determine the attack method, identify malicious payloads, and trace the timeline of events — focusing on how the attacker gained access, what tools and techniques were used, and how the malware operated post-compromise.

A single forensic artefact was provided:

- A PCAP capture containing network traffic from the compromised host

---

## PCAP Analysis

### Q1. The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed?

The first step was to identify how the attacker delivered the initial malware stage to the compromised machine. Since the scenario described the attacker executing a download command, I filtered the PCAP for outbound HTTP GET requests to look for file transfers.

```bash
tshark -r capture.pcapng -Y "http.request.method==GET" -T fields \
  -e ip.src -e ip.dst -e http.request.full_uri | grep -i "\.j*"
```

This revealed an HTTP GET request fetching a `.j*` file from an external IP address on a non-standard port, consistent with a first-stage malware dropper being pulled down from an attacker-controlled host.

> **Answer:** `http://45.126.209.4:222/mdm.jpg`

---

### Q2. Which hosting provider owns the associated IP address?

With the attacker's IP address identified from Q1, the next step was to determine which hosting provider was responsible for that IP range. 

```bash
whois 9.222.210.8 | grep -iE "org|netname|descr"
```

The WHOIS lookup returned the organisation associated with the IP block, identifying the hosting provider.

> **Answer:** `reliableSite.net`

---

### Q3. By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable?

To identify the malware payload, I exported all HTTP objects from the PCAP to examine the files that were transferred.

```bash
mkdir extracted
tshark -r capture.pcapng --export-objects http,extracted/
ls -la extracted/
```

This produced two files: `xlm.txt` and `mdm.jpg`. Running `file` on both revealed that neither was what its extension suggested — `mdm.jpg` was actually a UTF-8 text file containing a PowerShell script with a hex-encoded PE executable embedded inside it.

```bash
file mdm.jpg
# mdm.jpg: Unicode text, UTF-8 (with BOM) text, with very long lines (65514), with CRLF line terminators
```

Inspecting the file confirmed a large hex string variable (`$hexString_bbb`) beginning with `4D_5A_90` — the MZ magic bytes of a Windows PE executable. The hex values were underscore-delimited.

```bash
grep "hexString_bbb" mdm.jpg | sed 's/.*= "//;s/"//' | tr -d '_\n ' | xxd -r -p > extracted_payload.exe
```

Once extracted, the executable was hashed:

```bash
sha256sum extracted_payload.exe
```

> **Answer:** `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`

---

### Q4. What is the malware family label based on Alibaba?

With the SHA256 hash in hand, the sample was submitted to **VirusTotal** for threat intelligence analysis. Navigating to the **Detection** tab and locating the **Alibaba** vendor row revealed their classification label for the sample.

> **Answer:** `AsyncRat`

---

### Q5. What is the timestamp of the malware's creation?

The **Details** tab on the VirusTotal report includes PE header metadata, which contains the compilation timestamp embedded by the compiler at build time. This timestamp indicates when the malware executable was created.

> **Answer:** `2023-10-30 15:08`

---

### Q6. Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path.

To understand how the malware achieved stealthy process execution, I examined the loader script (`mdm.jpg`) in detail. The script contained several obfuscated string variables that, once deobfuscated by removing placeholder characters, revealed the full path of the binary being invoked.

The relevant lines were:

```powershell
$NA = 'C:\W########indow#############s\Mi####cr' -replace '#', ''
$AC = $NA + 'osof#####t.NET\Fra###mework\v4.0.303###19\R##egSvc#####s.exe' -replace '#', ''
```

Cleaning these strings by removing the `#` characters produces the full path to a legitimate .NET utility — a classic **Living Off the Land Binary (LOLBin)** technique where attackers abuse trusted, signed Windows executables to execute malicious code while evading detection.

> **Answer:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

---

### Q7. The script is designed to drop several files. List the names of the files dropped by the script.

Continuing the analysis of `mdm.jpg`, the script contained multiple `[IO.File]::WriteAllText()` calls, each writing a different payload to disk. These dropped files serve distinct purposes in the attack chain — a PowerShell script, a batch launcher, and a VBScript wrapper.

The following file write operations were identified:

```powershell
[IO.File]::WriteAllText("C:\Users\Public\Conted.ps1", $Content)
[IO.File]::WriteAllText("C:\Users\Public\Conted.bat", $Content)
```

A third file was also constructed using a VBScript block referencing `WScript.Shell`, indicating a `.vbs` file was also dropped.

> **Answer:** `Conted.ps1`, `Conted.bat`, `Conted.vbs`

---

## Conclusion

This investigation traced a multi-stage malware delivery chain through network traffic analysis and static script examination. The attack followed a clear progression from initial download to payload execution:

| Stage | Activity |
|-------|----------|
| **1. Delivery** | First-stage `.jpg` (PowerShell script) downloaded via HTTP from attacker-controlled host |
| **2. Payload Extraction** | Hex-encoded PE executable decoded from within the PowerShell script |
| **3. Execution** | LOLBin (`RegSvcs.exe`) abused to load and execute the decoded payload stealthily |
| **4. Persistence** | Multiple files dropped to `C:\Users\Public\` to support continued execution |
| **5. C2** | Extracted executable identified as a backdoor communicating with attacker infrastructure |

By correlating network artefacts with static script analysis and threat intelligence lookups, it was possible to reconstruct the full delivery chain and identify all key indicators of compromise.