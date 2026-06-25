# Session Key API Documentation

## Overview

The Session Key API provides endpoints for managing session keys (JWT or non-login UUIDs) in a whitelist.
All endpoints are available under the `/sessionkey` base path and accept cross-origin requests.

## Base URL
```
/sessionkey
```

## Request/Response Format

All endpoints accept JSON payloads and return JSON responses (where applicable).

### SessionKeyRequest Object

```json
{
  "sessionKey": "string",
  "sessionLength": "number (optional)"
}
```

- **sessionKey**: The session key identifier (UUID)
- **sessionLength**: Duration in minutes for which the session key should be valid (optional, defaults to configured value)

## Endpoints

### Add Session Key

Adds a new session key to the whitelist with a specified or default timeout period.

**Endpoint**: `POST /sessionkey/add`

**Request Body**:
```json
{
  "sessionKey": "example-key-123",
  "sessionLength": 60
}
```

**Response**:
- **200 OK**: Session key successfully added (empty response body)

**Notes**:
- If `sessionLength` is not provided, the system default timeout 
is taken from application properties (or 30 minutes if not defined there)
- The endpoint always returns 200 OK, even if the addition fails internally

### Check Single Session Key

Verifies if a single session key exists in the whitelist.

**Endpoint**: `POST /sessionkey/check`

**Request Body**:
```json
{
  "sessionKey": "example-key-123"
}
```

**Response**:
- **200 OK**: Session key is whitelisted (empty response body)
- **404 Not Found**: Session key is not whitelisted (empty response body)

### Check Multiple Session Keys

Checks multiple session keys and returns those that are NOT whitelisted.

**Endpoint**: `POST /sessionkey/keys`

**Request Body**:
```json
[
  {
    "sessionKey": "key-1"
  },
  {
    "sessionKey": "key-2"
  },
  {
    "sessionKey": "key-3"
  }
]
```

**Response**:
- **200 OK**: Returns array of session keys that are NOT whitelisted
```json
["key-1", "key-3"]
```

### Check Multiple Session Keys (String Format)

Alternative endpoint for checking multiple session keys using a comma-separated string format.

**Endpoint**: `POST /sessionkey/keysString`

**Request Body**:
```
key-1, key-2, key-3
```

**Response**:
- **200 OK**: Returns array of session keys that are NOT whitelisted
```json
["key-1", "key-3"]
```

### Delete Session Key

Removes a session key from the whitelist.

**Endpoint**: `POST /sessionkey/delete`

**Request Body**:
```json
{
  "sessionKey": "example-key-123"
}
```

**Response**:
- **200 OK**: Session key successfully deleted (empty response body)
- **404 Not Found**: Session key was not found in whitelist (empty response body)

## Error Handling

For the `/keys` and `/keysString` endpoints, if an exception occurs during processing, the error will be logged and re-thrown, potentially resulting in a 500 Internal Server Error response.

## Configuration

The default session key timeout period can be configured using the `sessionkey.whitelist.period` property (default: 30 minutes).

## Example Usage

### Adding a session key with custom timeout:
```bash
curl -X POST http://localhost:8080/sessionkey/add \
  -H "Content-Type: application/json" \
  -d '{"sessionKey": "my-session-123", "sessionLength": 120}'
```

### Checking if a session key is valid:
```bash
curl -X POST http://localhost:8080/sessionkey/check \
  -H "Content-Type: application/json" \
  -d '{"sessionKey": "my-session-123"}'
```

### Finding invalid keys from a list:
```bash
curl -X POST http://localhost:8080/sessionkey/keys \
  -H "Content-Type: application/json" \
  -d '[{"sessionKey": "key1"}, {"sessionKey": "key2"}]'
```