# VELTRIX Ingestion Adapters & Collector Configurations

This directory contains verified configuration templates and forwarder scripts for reverse proxies and edge CDNs:

- `nginx/`: Nginx JSON log format configuration and FluentBit tail forwarder.
- `apache/`: Apache HTTP Server CustomLog format and FluentBit forwarder.
- `cloudflare/`: Cloudflare Worker non-blocking `ctx.waitUntil()` edge telemetry forwarder.
