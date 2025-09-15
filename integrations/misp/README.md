# Wazuh – MISP Integration v2

This repository contains an enhanced version of the Wazuh ↔ MISP integration script.

## ✨ Overview

This version builds upon the official Wazuh repository script and introduces several improvements to make the integration more scalable, resilient, and production-ready.

## 🔍 Key Improvements

### 1. IOC Extraction
- **Original Wazuh script**: Hard-coded logic, single IOC extraction, limited to Sysmon and a few sources.  
- **Enhanced script**: Flexible key mapping (`SUPPORTED_KEYS`), dynamic nested JSON traversal, supports multiple IOC values (IPs, hashes, domains, URLs).

### 2. MISP Querying
- **Original**: Synchronous requests, one IOC per alert.  
- **Enhanced**: Asynchronous with `httpx`, concurrent lookups with semaphores, deduplication, retries with exponential backoff, and richer payload (context, tags, sightings).

### 3. Error Handling & Retry
- **Original**: Single local queue (`misp_queue.json`) for failed events.  
- **Enhanced**: Two persistence layers:  
  - Retry queue for socket failures.  
  - Separate directory for failed MISP enrichments (retried once MISP is available again).  
  Includes healthcheck before retries.

### 4. Logging
- **Original**: Basic plaintext file logging.  
- **Enhanced**: Structured logging with rotating file handler (10 MB × 5 backups), console + file output, and support for JSON logs.

### 5. Output to Wazuh
- **Original**: Limited enrichment (basic MISP fields).  
- **Enhanced**: Rich enrichment payload including:  
  - IOC values mapped to Wazuh keys.  
  - Flags for matched indicators.  
  - Full MISP attribute metadata (UUID, event info, threat level, etc.).  
  - Original alert context.

### 6. Code Quality & Extensibility
- **Original**: Procedural, minimal modularization, hard-coded.  
- **Enhanced**: Modular async design (`extract_all_iocs`, `misp_fetch`, `save_failed_misp_alert`, etc.), cleaner architecture, easier to extend to new data sources.

---

## ✅ Conclusion

Compared to the Wazuh repository script, this enhanced implementation is:

- More generic and reusable across diverse log sources.  
- Faster and more reliable with async I/O and retries.  
- Resilient against failures with multi-layer persistence.  
- Configurable with richer logging.  
- Provides significantly more enrichment data for correlation and dashboards.  
- Architecturally cleaner and easier to maintain.  

In short: the Wazuh repo script works for basic MISP lookups, but this version is **more production-ready, scalable, and informative**.

---

## 👨‍💻 Author

This enhanced integration was originally created by [Ratandeep18](https://github.com/Ratandeep18).  
We are publishing it here as **`v2`** in parallel to the official integration, to highlight the improvements and make it easier to use in production environments.
