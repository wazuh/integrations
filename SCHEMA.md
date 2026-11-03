# AI Agent Detection Schema

**Status: DRAFT.** This schema currently reflects only the `claude_code` integration. It will be extended once `codex_cli` and `gemini_cli` have real captured samples, per the project's own verification rule: no field is added here until it has been observed in a real, captured event.

## Purpose

A shared conceptual field set that every AI-agent-detection integration in this project normalizes toward, so that `ai_agent_host` and future cross-agent correlation rules can reason about "a tool call was accepted under a bypass mode" the same way regardless of which agent emitted it.

## Normalization note: dotted attribute names

OpenTelemetry attribute names use dots as a semantic-grouping convention (`service.name`, `event.name`, `session.id`). This project's shipper scripts (`otel_shipper.py`) rewrite every dot to an underscore (`service_name`, `event_name`, `session_id`) before the event reaches either Wazuh version. This is a deliberate normalization, not an artifact: Wazuh 5.0-rc's decoder expression language documents dotted paths only for genuine JSON nesting, and does not specify how to address a flat key that itself contains a literal dot. Rather than rely on unconfirmed behavior, every integration in this project ships data with underscored keys only.

## Shared conceptual fields (from claude_code)

**Note on the v5.0 column:** Wazuh 5.0-rc's decoder engine validates every mapped field name against its own built-in Wazuh Common Schema (WCS) at promotion time — a custom dotted field like `claude_code.tool_name` is rejected outright ("Field '...' is not defined in WCS schema and is not a temporary field"), confirmed empirically when attempting to add a `session.id` mapping (WCS has no `session.id` field; the attempt was reverted). Every v5.0 field below is therefore an existing WCS field being reused for this purpose, not a project-defined namespace — see `claude_code_wazuh_v5.0/ruleset/decoders/decoder_claude-code_0.yml` for the authoritative mapping, live Log-test validated (see VERIFY.md).

| Shared field | Claude Code OTel source | v4.x XML field | v5.0 WCS field | Notes |
| --- | --- | --- | --- | --- |
| Agent session ID | `session.id` attribute | `session_id` | *(not mapped)* | No WCS field exists for a session identifier; confirmed gap, see VERIFY.md — not available for v5.0 cross-event/cross-agent correlation |
| Agent user ID | `user.id` attribute | `user_id` | `user.id` | Anonymized hash, not a real identity |
| Event name | `body.stringValue` (e.g. `claude_code.tool_decision`) | `event_body` | `message` (via `event_name` attribute) | Dotted event-name string, not an attribute itself in the raw OTLP, but `event.name`/`event_name` attribute carries the short form (`tool_decision`) |
| Tool name | `tool_name` attribute | `tool_name` | `process.name` | Only present on `tool_decision`/`tool_result` |
| Tool call ID | `tool_use_id` attribute | `tool_use_id` | `event.id` | Joins `tool_decision` and `tool_result` for the same call |
| Permission decision | `decision` attribute (`accept`/`reject`) | `decision` | `event.action` and `event.outcome` (both set to the same value) | Only on `tool_decision` |
| Decision source | `source` attribute | `source` | `event.provider` | Values observed: `config`, `hook`. Docs also list `user_permanent`/`user_temporary`/`user_abort`/`user_reject`, not yet observed live — see VERIFY.md |
| Permission mode | `permission_mode` attribute | `permission_mode` | `tags` | Only on `tool_decision`; values observed: `default`, `bypassPermissions` |
| Tool call success | `success` attribute | `success` | `event.outcome` | Only on `tool_result` |
| Tool arguments (raw) | `tool_input` attribute (requires `OTEL_LOG_TOOL_DETAILS=1`) | `tool_input` | `file.path` | JSON string, e.g. `{"file_path": "..."}` |
| Tool-specific parameters (raw) | `tool_parameters` attribute (requires `OTEL_LOG_TOOL_DETAILS=1`) | `tool_parameters` | `process.command_line` (extracted `full_command` substring only, via a two-step `parse_json` + field reference) | Only populated for Bash/MCP/Skill/Agent tools per the official docs; Read/Write/Edit never get this field, only `tool_input` |
| Error type | `error_type` attribute | `error_type` | `error.message` | Only present when a tool call fails |

## v4.x rule ID ranges (no registry exists in this fork — re-grep before allocating a new block)

| Integration | Range |
| --- | --- |
| `caddy_integration_wazuh_v4.14.6` (existing) | 996000-996032 |
| `claude_code_wazuh_v4.14` | 997000-997099 |
| `codex_cli_wazuh_v4.14` | 997100-997199 (reserved, not yet used) |
| `gemini_cli_wazuh_v4.14` | 997200-997299 (reserved, not yet used) |
| `cursor_wazuh_v4.14` | 997300-997399 (reserved, not yet used) |
| `mcp_servers_wazuh_v4.14` | 997400-997499 (reserved, not yet used) |
| `ai_agent_host_wazuh_v4.14` | 997500-997599 (reserved, not yet used) |
