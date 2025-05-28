# CTF Initial Recon Script

**initial_recon.sh is a Bash-based script desgined to assist in the initial recon for CTFs**

___

## Features
- **nmap** for top 1000 ports and continue initial recon on found ports
- **ports included** 22, 80, 8080, 443
- **ffuf** 80 | 8080 | 443 for hidden directories and files

## Usage

Ensure you have execution permissions:

```bash
chmod +x initial_recon.sh
./initial_recon.sh $IP
```

## Requirements
- bash
- nmap
- curl
- whatweb
- ffuf
- openssl

## Output
```kotlin
- loot/
- |-- ini_recon-10.0.2.6-20250528-0900.txt
- |-- ini_recon-10.0.2.7-20250528-1000.txt
```

# Author
Developed by RBfP
Website: cyberforks.com
Github: github.com/rbfp
