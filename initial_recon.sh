#!/bin/bash

if [-z "$1" ]; then
	echo "Usage: $0 <target-ip>"
	exit 1
fi

TARGET=$1
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="./loot"
OUTPUT_FILE="${OUTPUT_DIR}/external-${TARGET}-${TIMESTAMP}.txt"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting external recon on $TARGET"
echo "[*] Results will be saved to $OUTPUT_FILE"

# step 1: initial top 1000 TCP scan
echo -e "\n[*] Running top 1000 TCP port scan..." | tee -a "$OUTPUT_FILE"
nmap -Pn -sS -n -T4 "$TARGET" -oG - | tee -a "$OUTPUT_FILE" > temp.grep

# step 2: extract open ports
OPEN_PORTS=$(grep -oP '\d+/open' temp.grep | cut -d'/' -f1 | head -n 5)
echo -e "\n[*] Top Open Ports:" | tee -a "$OUTPUT_FILE"
echo -e "$OPEN_PORTS" | tee -a "$OUTPUT_FILE"


# step 3: follow up enumeration based on open ports
for PORT in $OPEN_PORTS; do
	case $PORT in
		22)
			echo -e "\n[*] Port 22 (SSH) found. Running ssh banner grab..." | tee -a "$OUTPUT_FILE"
			nc -vz "$TARGET" 22 2>&1 | tee -a "$OUTPUT_FILE"
			;;
		80|8080)
			echo -e "\n[*] Port $PORT (HTTP) found. Running curl + whatweb + robots.txt" | tee -a "$OUTPUT_FILE"
			curl -Is "http://$TARGET:$PORT" | tee -a "$OUTPUT_FILE"
			whatweb "http://$TARGET:$PORT" | tee -a "$OUTPUT_FILE"
			curl -s "http://$TARGET:$PORT/robots.txt" | tee -a "$OUTPUT_FILE"
			
			echo -e "\n[*] Running ffuf against $TARGET/FUZZ w/ directory-list-2.3-medium.txt" | tee -a "$OUTPUT_FILE"
			ffuf -u "http://$TARGET:$PORT/FUZZ" \
				-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
				-e .php,.zip,.txt,.bak \
				-mc 200-403 \
				-c -v -s | tee -a "$OUTPUT_FILE"
			;;
		443)
			echo -e "\n[*] Port 443 (HTTPS) found. Running SSL scan..." | tee -a "$OUTPUT_FILE"
			echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null | tee -a "$OUTPUT_FILE"
			echo -e "\n[*] Checking robots.txt" | tee -a "$OUTPUT_FILE"
			curl -sk "https://$TARGET/robots.txt" | tee -a "$OUTPUT_FILE"


			echo -e "\n[*] Running ffuf w/ directory-list-2.3-medium.txt" | tee -a "$OUTPUT_FILE"
			ffuf -u "https://$TARGET/FUZZ" \
				-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
				-e .php,.zip,.txt,.bak \
				-mc 200-403 \
				-c -v -s | tee -a "$OUTPUT_FILE"
			;;
		3306)
			echo -e "\n[*] Port 3306 (MySQL) found. Checking response..." | tee -a "$OUTPUT_FILE"
			timeout 5 bash -c "cat < /dev/null > /dev/tcp/$TARGET/3306" 2>/dev/null && echo "MySQL port open" | tee -a "$OUTPUT_FILE"
			;;
		*)
			echo -e "\n[*] Port $PORT found. No custom follow-up defined yet." | tee -a "$OUTPUT_FILE"
			;;
	esac
done

rm -f temp.grep
rm -f temp_ffuf_*

echo -e "\n[*] External recon complete. Results in $OUTPUT_FILE"

		 
