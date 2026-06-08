#!/bin/bash
set -euo pipefail

PLUGIN_DIR="/usr/share/wazuh-dashboard/plugins/assistantDashboards"

cp $PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js $PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js.bak
cp $PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js.br $PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js.br.bak
cp $PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js.gz $PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js.gz.bak
cp $PLUGIN_DIR/target/public/assistantDashboards.plugin.js $PLUGIN_DIR/target/public/assistantDashboards.plugin.js.bak
cp $PLUGIN_DIR/target/public/assistantDashboards.plugin.js.br $PLUGIN_DIR/target/public/assistantDashboards.plugin.js.br.bak
cp $PLUGIN_DIR/target/public/assistantDashboards.plugin.js.gz $PLUGIN_DIR/target/public/assistantDashboards.plugin.js.gz.bak

rm $PLUGIN_DIR/target/public/assistantDashboards.plugin.js.br
rm $PLUGIN_DIR/target/public/assistantDashboards.plugin.js.gz
rm $PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js.gz
rm $PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js.br

sed -i -e "s|OpenSearch Assistant|Dashboard assistant|g" $PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js
sed -i -e "s|OpenSearch Assistant|Dashboard assistant|g" $PLUGIN_DIR/target/public/assistantDashboards.plugin.js
sed -i -e "s|he Dashboard assistant|he dashboard assistant|g" $PLUGIN_DIR/target/public/assistantDashboards.plugin.js
sed -i -e "s|base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMzAuODMzMyAzOS44NTlDMzEuODk2MiAzOS40Mzk4IDMxLjg2OCAzOC4xMTU5IDMxLjg2OCAzNy4wMjk0VjMyLjY2NjZIMzQuMjg1N0MzNy40NDE3IDMyLjY2NjYgNDAgMzAuMjUzOSA0MCAyNy4yNzc1VjcuMzg5MTRDND.*InVzZXJTcGFjZU9uVXNlIj4KICAgIDxzdG9wIHN0b3AtY29sb3I9IiMwMEEzRTAiLz4KICAgIDxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzAwQTNFMCIgc3RvcC1vcGFjaXR5PSIwIi8+CiAgICA8L2xpbmVhckdyYWRpZW50PgogICAgPC9kZWZzPgo8L3N2Zz4=|base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCIKCSB2aWV3Qm94PSIwIDAgNTEyIDUxMiIgc3R5bGU9ImVuYWJsZS1iYWNrZ3JvdW5kOm5ldyAwIDAgNTEyIDUxMjsiIHhtbDpzcGFjZT0icHJlc2VydmUiPgo8Zz4KCTxwYXRoIGZpbGw9IiMwMDZCQjQiIGQ9Ik00MDQuNSwyMS4yVjBoLTI5N0M0OC45LDAsMS40LDQ3LjUsMS40LDEwNi4xdjE2OS43YzAsNTguNiw0Ny41LDEwNi4xLDEwNi4xLDEwNi4xaDI0Ni45TDUxMC42LDUxMlYxMDYuMQoJCUM1MTAuNiw0Ny41LDQ2My4xLDAsNDA0LjUsMFYyMS4ydjIxLjJjMzUuMSwwLjEsNjMuNiwyOC41LDYzLjYsNjMuNnYzMTUuM2wtOTguNC04MkgxMDcuNWMtMzUuMS0wLjEtNjMuNi0yOC41LTYzLjYtNjMuNmwwLTE2OS43CgkJYzAuMS0zNS4xLDI4LjUtNjMuNiw2My42LTYzLjZoMjk3VjIxLjJ6IE00MDQuNSwxMjcuM0gxMjguN3Y0Mi40aDI3NS44VjEyNy4zeiBNNDA0LjUsMjEyLjFIMjEzLjZ2NDIuNGgxOTAuOVYyMTIuMXoiLz4KPC9nPgo8L3N2Zz4K|" $PLUGIN_DIR/target/public/assistantDashboards.plugin.js

gzip -c -9 "$PLUGIN_DIR/target/public/assistantDashboards.plugin.js" > "$PLUGIN_DIR/target/public/assistantDashboards.plugin.js.gz"
gzip -c -9 "$PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js" > "$PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js.gz"

brotli -q 11 -f "$PLUGIN_DIR/target/public/assistantDashboards.plugin.js" -o "$PLUGIN_DIR/target/public/assistantDashboards.plugin.js.br"
brotli -q 11 -f "$PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js" -o "$PLUGIN_DIR/target/public/assistantDashboards.chunk.10.js.br"
