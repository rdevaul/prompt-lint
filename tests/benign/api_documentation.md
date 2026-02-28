# API Reference

## Authentication
All requests require a Bearer token in the Authorization header.

## Endpoints

### POST /v1/audio/transcriptions
Transcribe an audio file.

**Parameters:**
- `file` (required): Audio file, multipart/form-data
- `model` (optional): Model ID, default "whisper-1"
- `language` (optional): ISO 639-1 language code

**Response:**
```json
{"text": "transcription result here"}
```

### GET /health
Returns service health status.

**Response:** `{"status": "ok"}`

## Rate limits
100 requests per minute per API key. Exceeding this returns HTTP 429.
