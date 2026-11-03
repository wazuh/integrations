#!/bin/bash
# Wazuh - Yara active response
read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)
LOG_FILE="logs/active-responses.log"

size=0
actual_size=$(stat -c %s ${FILENAME})
while [ ${size} -ne ${actual_size} ]; do
  sleep 1
  size=${actual_size}
  actual_size=$(stat -c %s ${FILENAME})
done

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]; then
  echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> ${LOG_FILE}
  exit 1
fi

yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"
if [[ $yara_output != "" ]]; then
  while read -r line; do
    echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
  done <<< "$yara_output"
fi
exit 0
