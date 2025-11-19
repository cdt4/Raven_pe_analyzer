# Raven EXE Deconstructor v2
### Paranoid PE File Analysis Tool for Windows Executables

---

##  Overview
Raven is an advanced **static analysis tool** for dissecting Windows PE (Portable Executable) files with a **paranoid, security-first mindset**.  
It assumes *everything* is suspicious until proven otherwise.

> "When you're analyzing a file with a malware tool, it's probably for a reason."

---

##  Features

### Deep Static Analysis
- **PE Structure Analysis**: Complete dissection of PE headers, sections, and metadata  
- **Entropy Analysis**: Shannon entropy calculation with visual graphing  
- **Import/Export Analysis**: Detailed inspection of imported and exported functions  
- **String Extraction**: Classified strings (URLs, IPs, file paths, etc.)  
- **Resource Analysis**: Full resource directory examination  

### Suspicious Behavior Detection
- **Packer Detection**: 20+ packers and cryptors recognized by signature  
- **API Monitoring**: Flags 100+ Windows APIs abused by malware  
- **Anomaly Detection**: Identifies broken or suspicious PE structures  
- **Risk Assessment**: Heuristic risk scoring (`Critical`, `High`, `Medium`, `Low`)  

### Advanced Visualization
- **Entropy Graphs & Byte Maps** via Matplotlib  
- **Interactive GUI**: PyQt5-based tabbed interface  
- **Hex Viewer**: Built-in hex dump display  
- **Function Analysis**: Smart disassembly with function detection  

### Multi-Format Reporting
- **JSON Export** for automation  
- **HTML Reports** with rich formatting and visuals  
- **Text Reports** for quick summaries  
- **Filtered String Export** for triage  

---

##  Installation

### Requirements

pip install -r requirements.txt
requirements.txt

```bash
ini
Copy code
pefile==2023.2.7
capstone==5.0.0
colorama==0.4.6
PyQt5==5.15.9
matplotlib==3.7.1
numpy==1.24.3
ssdeep==3.4
```

## Cli Usage

### Basic Analysis
```bash
python Raven_exe_deconstructor.py <path_to_exe>
Advanced Analysis Options
bash
Disassemble code sections
python Raven_exe_deconstructor.py file.exe -d

Extract and classify strings
python Raven_exe_deconstructor.py file.exe -s

Show detailed entropy analysis
python Raven_exe_deconstructor.py file.exe -e

Detect function boundaries
python Raven_exe_deconstructor.py file.exe -f

Run all analysis options
python Raven_exe_deconstructor.py file.exe -a

Save output to file
python Raven_exe_deconstructor.py file.exe -d -o disassembly.txt
python Raven_exe_deconstructor.py file.exe -s -o strings.txt

Save full analysis report
python Raven_exe_deconstructor.py file.exe -save json   # JSON format
python Raven_exe_deconstructor.py file.exe -save txt    # Text format  
python Raven_exe_deconstructor.py file.exe -save html   # HTML format

Custom report format
python Raven_exe_deconstructor.py file.exe -format json  # JSON output to console
python Raven_exe_deconstructor.py file.exe -format html  # HTML output to console
Example Commands
bash
Quick analysis with text report
python Raven_exe_deconstructor.py suspicious_file.exe

Comprehensive analysis with HTML report
python Raven_exe_deconstructor.py malware.exe -a -save html

Extract strings and save to file
python Raven_exe_deconstructor.py target.exe -s -o extracted_strings.txt

Disassemble and save to file
python Raven_exe_deconstructor.py binary.exe -d -o disassembly.asm
Output Options
Default: Text report to console


-o/--output: Save specific analysis results to file

-save: Save complete analysis report in specified format

-format: Control console output format (text/json/html)

```


##  Understanding the Results
Why Legitimate Tools Flag as High Risk
Raven is intentionally paranoid. Many legitimate tools perform malware-like actions:

VPN Clients: Kernel-level networking, routing table modification

System Utilities (e.g. Rufus): Direct disk writes, boot sector modification

Development Tools: Process injection, API hooking, memory manipulation

Risk Assessment Levels
🟥 Critical: Multiple high-confidence indicators

🟧 High: Several suspicious techniques

🟨 Medium: Some red flags

🟩 Low: Minimal suspicious traits

## Interpretation Guide
High Entropy Sections

> 7.5: Likely packed/encrypted

6.5–7.5: Possibly compressed or obfuscated

< 6.5: Normal code/data

Suspicious Imports

CreateRemoteThread: Debuggers & malware

VirtualAllocEx: Utilities & malware

RegSetValueEx: Installers & persistence mechanisms

Strings

URLs/IPs: Possible C2 infrastructure or update servers

File Paths: Drop locations or install targets

##  FAQ
### Q: Why does my legit software show as High Risk?
### A: Because it uses techniques malware also uses. Raven flags the technique, not the intent.

### Q: Should I delete everything marked Critical?
### A: No! Raven will mark things as critical Even when they may not be malware. Context is important is this a random exe you found on your desktop? or is it the discord installer

### Q: What makes Raven different?
### A: Its made by my pet goldfish theodore

##  Best Practices
Use multiple tools (Raven + VirusTotal + sandboxing)

Always check digital signatures

Research publishers (unknown = higher risk)

Consider file context (where it came from, why it’s running)

When in doubt: contain and investigate further


## Notes from the dev
This tool ISNT FINISHED nor will it get a very active update cycle

Expect it to be slow, Its made in python what do you expect


I may update it in the future to use rust but thats a long way away


## Updates
v 2.0 split the 2 monolithic files into split up sub folders and ect
v 1 release 


# ⚠️ Disclaimer
### Raven detects potentially malicious techniques.
### It may flag legitimate software that uses sensitive operations.
### Always verify with multiple sources before acting.

### A suspicious rating means “investigate further,” not “definitely malicious.”