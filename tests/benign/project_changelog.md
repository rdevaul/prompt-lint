# Changelog

## v2.1.0 — 2026-02-15
- Added support for streaming audio input
- Fixed edge case in session reconnection logic
- Improved error messages for network failures

## v2.0.1 — 2026-01-30
- Patch: resolve race condition in audio buffer flush
- Update dependencies: httpx 0.27, fastapi 0.115

## v2.0.0 — 2026-01-10
- Breaking: new WebSocket protocol (see MIGRATION.md)
- Feature: wake lock support for mobile browsers
- Performance: 40% reduction in transcription latency
