#!/bin/bash

# ===============================
# OpenVAS Combined JSON Export (Results + NVTS + Report Creation Time)
# ===============================

DB_NAME="gvmd"
DB_USER="_gvm"
OUTPUT_DIR="/opt/openvas"
SOCKET_DIR="/var/run/postgresql"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/openvas_combined.json"

echo "Exporting combined results of nvts, results, and reports (creation time) to $OUTPUT_FILE ..."

# Start JSON array
echo "[" > "$OUTPUT_FILE"

# Stream combined JSON row by row
sudo -u _gvm psql -d "$DB_NAME" -h "$SOCKET_DIR" -t -A -F "" -c "
SELECT row_to_json(combined)
FROM (
    SELECT
        r.id AS result_id,
        r.report AS report_id,
        r.host,
        r.port,
        r.severity,
        r.description AS result_description,
        n.name AS nvt_name,
        n.oid AS nvt_oid,
        n.family AS nvt_family,
        n.cvss_base AS nvt_cvss_base,
        n.cve AS nvt_cve,
        rep.creation_time AS report_creation_epoch,
        to_timestamp(rep.creation_time) AS report_creation_time
    FROM results r
    LEFT JOIN nvts n ON r.nvt = n.oid
    LEFT JOIN reports rep ON r.report = rep.id
    ORDER BY r.report, r.host
) combined;" | awk 'NR>0 {print (NR==1?"":"") $0}' >> "$OUTPUT_FILE"

# End JSON array
echo "]" >> "$OUTPUT_FILE"

echo "Export completed. Combined JSON saved at $OUTPUT_FILE"
