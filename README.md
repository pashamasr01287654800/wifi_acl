# wifi_acl.sh

<h1 align="center">
  <pre>
   ██     ██ ██  ███████ ██ 
   ██     ██ ██  ██      ██ 
   ██  █  ██ ██  █████   ██ 
   ██ ███ ██ ██  ██      ██ 
    ███ ███  ██  ██      ██ 
  </pre>
  🚀 WiFi ACL & Deauth Automation Script 🚀
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Bash-Script-blue?logo=gnu-bash&logoColor=white">
  <img src="https://img.shields.io/badge/License-Educational-green">
  <img src="https://img.shields.io/badge/Tools-Airodump%20%7C%20MDK3-orange">
  <img src="https://img.shields.io/github/stars/pashamasr01287654800/wifi_acl?style=social">
</p>

---

## ✨ Overview
This Bash script automates **wireless client control** via MAC filtering and deauthentication attacks using `mdk3` and `airodump-ng`.

It supports two modes:

- 🟢 **Whitelist Mode (`-w`)** → Only allow devices in the whitelist, deauthenticate all others.
- 🔴 **Blocklist Mode (`-b`)** → Detect unknown clients, add them to the blocklist, and deauthenticate them.

> ⚠ **DISCLAIMER:** Educational and authorized penetration testing only!  
> Unauthorized use is **illegal**.

---

## ⚡ Features
✅ Auto monitor mode activation  
✅ Interactive whitelist setup  
✅ Dynamic blocklist updates  
✅ Clean process & interface management  
✅ Fully modular functions  

---

## 🛠 Requirements
Make sure these tools are installed:
- `iw`
- `airmon-ng`
- `airodump-ng`
- `mdk3`
- `awk`, `grep`, `sed`

---

## 📥 Installation
```bash
git clone https://github.com/pashamasr01287654800/wifi_acl.git
cd wifi_acl
chmod +x wifi_acl.sh


---

🚀 Usage

Run as root:

sudo ./wifi_acl.sh

Steps:

1. Add MAC addresses to whitelist (optional).


2. Choose mode → w or b.


3. Script captures clients and runs mdk3 attacks.


4. Blocklist updates automatically in blocklist mode.




---

📂 Output Files

whitelist.txt → Allowed MACs.

blocklist.txt → Blocked MACs.

temp_capture_files/ → Temporary captures (auto-cleaned).



---

🖥 Example

Do you want to add whitelist MACs now? (yes/no): yes
Enter the MAC address: 00:11:22:33:44:55
Added to whitelist.
Add another? (yes/no): no
Use whitelist or blocklist? (w/b): b
Starting capture & deauth...


---

⚖ Legal Notice

For educational and authorized use only.
Do not use on networks without permission.


---

👨‍💻 Author

pashamasr01287654800
