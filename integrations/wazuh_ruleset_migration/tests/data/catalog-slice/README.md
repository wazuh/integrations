# 5.x catalog slice

Files copied byte for byte from the Wazuh 5.0 content catalog, context `rc1-t1-ruleset-5` offset 1833 (consumer
`public-ruleset-5`, one JSON per asset, `payload.document`).

| Kind | Assets |
|---|---|
| `policies/` | The snapshot policy (lists all 127 integrations) |
| `integrations/` | `wazuh-core` (holds the root `decoder/core-wazuh-message/0`), `system-auth` |
| `decoders/` | `core-wazuh-message`, `syslog`, `docker-container-logs`, `system-auth` |
| `kvdbs/` | The two KVDBs of `wazuh-core` |
| `manifest.json` | The pull manifest (counts are those of the whole snapshot) |

The tests copy this slice to a temporary directory and keep only these two integrations in the policy's list, so the
catalog is complete. The decoders use the helper names of that offset; the engine build is not part of these tests.
