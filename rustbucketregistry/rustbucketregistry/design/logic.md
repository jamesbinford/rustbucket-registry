# Rustbucket Registry Business Logic

## Overview
The Rustbucket Registry Business Logic is responsible for managing the registration of rustbuckets in the registry, and for executing pull-based updates to the registry, as well as pull-based extractions of registry logs from the rustbuckets.

## Registration Process
1. The Rustbucket will send a POST request to the `/register_bucket` endpoint with the following body:
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
2. The Rustbucket Registry Business Logic will validate the request and return a response with the following body:
```json
{
    "status": "string"
}
```

## Bucket Update Process
1. The Rustbucket Registry Business Logic will execute a pull-based update to the registry by pulling the IP address of each bucket from the registry and sending a GET request to the `/update_bucket` endpoint.
```url
GET https://ip_address/update_bucket
```
2. The Rustbucket Registry Business Logic will validate the request and return a response with the following body:
```json
{
    "status": "string",
    "updates": [
        {
            "name": "string",
            "ip_address": "string",
            "operating_system": "string",
            "cpu_usage": "string",
            "memory_usage": "string",
            "disk_space": "string",
            "uptime": "string",
            "connections": "string"
        }
    ]
}
```

## Bucket Log Extraction Process
1. The Rustbucket Registry Business Logic will execute a pull-based log extraction from each bucket by pulling the IP address of each bucket from the registry and sending a GET request to the `/extract_logs` endpoint.
```url
GET https://ip_address/extract_logs
```
2. The Rustbucket Registry Business Logic will validate the request and return a response containing the logs of the bucket.
```file
logs.txt
```
3. The Rustbucket Registry Business Logic will store the logs in a file in an S3 bucket, which is configured in settings.py. 


## Bucket Log Parsing Process
1. Every hour, the Rustbucket Log Parsing Process will execute and pull the logs from the S3 bucket, which is configured in settings.py.
2. The Rustbucket Log Parsing Process will parse each log and store it in a MySQL database which is also configured in settings.py.
3. The logs database table will be called `logs` and will have the following columns:
```sql
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    ip_address VARCHAR(255) NOT NULL,
    log TEXT NOT NULL,
    log_size INT NOT NULL, #Size in MB
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```


## Bucket Log Analysis Process
1. Every four hours, the Rustbucket Log Analysis Process will execute and pull the logs from the MySQL database, which is configured in settings.py.
2. The Rustbucket Log Analysis Process will kick off a workflow in which Claude will analyze the logs and return a "Log Analysis By Claude."
3. The "Log Analysis by Claude" will be stored in a MySQL database table called `log_analysis` and will have the following columns:
```sql
CREATE TABLE log_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    ip_address VARCHAR(255) NOT NULL,
    log_analysis TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

