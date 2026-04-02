#!/bin/bash

OUTPUT="./benign_files"
mkdir -p "$OUTPUT"
COUNT=500

echo "[+] Generating $COUNT benign files in $OUTPUT..."

for i in $(seq 1 $COUNT); do
  # Pick a random extension
  EXTENSIONS=(".txt" ".log" ".md" ".csv" ".json")
  EXT=${EXTENSIONS[$RANDOM % ${#EXTENSIONS[@]}]}
  FILENAME="benign_${i}${EXT}"

  case "$EXT" in
    .txt)
      echo "This is a sample text file number $i. Created for dataset purposes." > "$OUTPUT/$FILENAME"
      ;;
    .log)
      echo "[$(date)] INFO: Process $i started successfully. No errors found." > "$OUTPUT/$FILENAME"
      ;;
    .md)
      printf "# Document $i\n\nThis is a benign markdown file.\n\n## Section\nSample content for file $i." > "$OUTPUT/$FILENAME"
      ;;
    .csv)
      printf "id,name,value\n$i,sample_$i,$RANDOM" > "$OUTPUT/$FILENAME"
      ;;
    .json)
      printf '{"id": %d, "name": "sample_%d", "value": %d}' $i $i $RANDOM > "$OUTPUT/$FILENAME"
      ;;
  esac

  echo "[+] Created $FILENAME"
done

echo "[+] Done. $COUNT benign files saved in $OUTPUT"
