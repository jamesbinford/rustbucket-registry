# Rustbucket Registry API Specifications
## Overview
The Rustbucket Registry API provides a RESTful interface for managing rustbucket entries in the registry.

## Base URL
``https://api.example.com/v1/register_bucket``

## Authentication
No authentication is required for this API. Instead the Rustbucket will generate a unique token and send it in the request body. It is up to the administrator of the Registry to approve the registration of the Rustbucket.

## API Endpoints
### Register Rustbucket
``POST /register_bucket``

#### Request Body
```json
{
    "name": "string",
    "ip_address": "string",
    "operating_system": "string",
    "cpu_usage": "string",
    "memory_usage": "string",
    "disk_space": "string",
    "uptime": "string",
    "connections": "string",
    "token": "string"
}
```

#### Response and Body
* 200 - OK
* 400 - Bad Request
* 500 - Internal Server Error
```json
{
    "status": "string"
}
```
