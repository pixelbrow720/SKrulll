# SKrulll API Documentation

This document provides comprehensive documentation for the SKrulll REST API, which allows you to interact with the SKrulll platform programmatically.

## API Overview

The SKrulll API is a RESTful API that uses JSON for request and response bodies. It provides endpoints for managing tasks, retrieving scan results, and controlling the SKrulll platform.

### Base URL

All API endpoints are relative to the base URL:

```
https://your-skrulll-instance/api
```

For local development, this would typically be:

```
http://localhost:5000/api
```

### Authentication

The API supports two authentication methods:

1. **API Key Authentication**: For most API endpoints
2. **JWT Token Authentication**: For user-specific operations

#### API Key Authentication

To use API key authentication, include the API key in the `X-API-Key` header:

```
X-API-Key: your-api-key
```

#### JWT Token Authentication

To use JWT token authentication, include the token in the `Authorization` header:

```
Authorization: Bearer your-jwt-token
```

To obtain a JWT token, use the `/auth/login` endpoint.

### Response Format

All API responses follow a standard format:

```json
{
  "status": "success",
  "message": "Operation completed successfully",
  "data": {
    // Response data specific to the endpoint
  }
}
```

For error responses:

```json
{
  "status": "error",
  "message": "Error message",
  "code": 400,
  "details": {
    // Additional error details
  }
}
```

## API Endpoints

### Authentication

#### Login

```
POST /auth/login
```

Authenticate a user and obtain a JWT token.

**Request Body:**

```json
{
  "username": "your-username",
  "password": "your-password"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Login successful",
  "data": {
    "access_token": "your-jwt-token",
    "refresh_token": "your-refresh-token",
    "token_type": "Bearer",
    "expires_in": 86400
  }
}
```

#### Refresh Token

```
POST /auth/refresh
```

Refresh an expired JWT token.

**Request Body:**

```json
{
  "refresh_token": "your-refresh-token"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Token refreshed successfully",
  "data": {
    "access_token": "your-new-jwt-token",
    "token_type": "Bearer",
    "expires_in": 86400
  }
}
```

### Tasks

#### List Tasks

```
GET /tasks
```

Retrieve a list of tasks.

**Query Parameters:**

- `module` (optional): Filter tasks by module
- `status` (optional): Filter tasks by status

**Response:**

```json
{
  "status": "success",
  "message": "Tasks retrieved successfully",
  "data": {
    "tasks": [
      {
        "id": "task-id-1",
        "name": "Task Name",
        "description": "Task Description",
        "module": "module.name",
        "target": "target",
        "status": "completed",
        "created_at": "2025-05-10T08:30:00Z",
        "completed_at": "2025-05-10T08:35:00Z",
        "result": {
          // Task-specific result data
        }
      }
    ],
    "count": 1
  }
}
```

#### Create Task

```
POST /tasks
```

Create a new task.

**Request Body:**

```json
{
  "name": "Task Name",
  "description": "Task Description",
  "module": "module.name",
  "target": "target",
  "options": {
    // Module-specific options
  },
  "priority": 1,
  "tags": ["tag1", "tag2"]
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Task created successfully",
  "data": {
    "task": {
      "id": "new-task-id",
      "name": "Task Name",
      "description": "Task Description",
      "module": "module.name",
      "target": "target",
      "status": "scheduled",
      "created_at": "2025-05-10T10:00:00Z"
    }
  }
}
```

#### Get Task

```
GET /tasks/{task_id}
```

Retrieve a specific task by ID.

**Response:**

```json
{
  "status": "success",
  "message": "Task retrieved successfully",
  "data": {
    "task": {
      "id": "task-id",
      "name": "Task Name",
      "description": "Task Description",
      "module": "module.name",
      "target": "target",
      "status": "completed",
      "created_at": "2025-05-10T08:30:00Z",
      "completed_at": "2025-05-10T08:35:00Z",
      "result": {
        // Task-specific result data
      }
    }
  }
}
```

#### Update Task

```
PUT /tasks/{task_id}
```

Update a specific task by ID.

**Request Body:**

```json
{
  "name": "Updated Task Name",
  "description": "Updated Task Description",
  "status": "paused"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Task updated successfully",
  "data": {
    "task": {
      "id": "task-id",
      "name": "Updated Task Name",
      "description": "Updated Task Description",
      "status": "paused",
      "updated_at": "2025-05-10T10:15:00Z"
    }
  }
}
```

#### Delete Task

```
DELETE /tasks/{task_id}
```

Delete a specific task by ID.

**Response:**

```json
{
  "status": "success",
  "message": "Task deleted successfully"
}
```

#### Get Task Status

```
POST /tasks/status
```

Get the status of multiple tasks.

**Request Body:**

```json
{
  "task_ids": ["task-id-1", "task-id-2"]
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Task statuses retrieved successfully",
  "data": {
    "tasks": [
      {
        "id": "task-id-1",
        "status": "completed",
        "progress": 100,
        "updated_at": "2025-05-10T08:35:00Z"
      },
      {
        "id": "task-id-2",
        "status": "running",
        "progress": 65,
        "updated_at": "2025-05-10T09:10:00Z"
      }
    ]
  }
}
```

### Modules

#### List Modules

```
GET /modules
```

Retrieve a list of available modules.

**Response:**

```json
{
  "status": "success",
  "message": "Modules retrieved successfully",
  "data": {
    "modules": [
      {
        "id": "osint.domain_recon",
        "name": "Domain Reconnaissance",
        "description": "Gather information about a domain",
        "category": "OSINT",
        "options": {
          "whois": {
            "type": "boolean",
            "default": true,
            "description": "Perform WHOIS lookup"
          },
          "dns": {
            "type": "boolean",
            "default": true,
            "description": "Perform DNS lookups"
          },
          "subdomains": {
            "type": "boolean",
            "default": true,
            "description": "Discover subdomains"
          }
        }
      }
    ],
    "count": 1
  }
}
```

### Scan Configurations

#### Create Scan Configuration

```
POST /scan-configs
```

Create a new scan configuration.

**Request Body:**

```json
{
  "name": "Config Name",
  "description": "Config Description",
  "modules": ["module1", "module2"],
  "options": {
    "module1": {
      "option1": "value1"
    },
    "module2": {
      "option2": "value2"
    }
  },
  "is_default": false
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Scan configuration created successfully",
  "data": {
    "config": {
      "id": "config-id",
      "name": "Config Name",
      "description": "Config Description",
      "modules": ["module1", "module2"],
      "options": {
        "module1": {
          "option1": "value1"
        },
        "module2": {
          "option2": "value2"
        }
      },
      "is_default": false,
      "created_at": "2025-05-10T10:30:00Z"
    }
  }
}
```

### Reports

#### Create Report

```
POST /reports
```

Create a new report from task results.

**Request Body:**

```json
{
  "title": "Report Title",
  "description": "Report Description",
  "task_ids": ["task-id-1", "task-id-2"],
  "format": "pdf"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Report generation started",
  "data": {
    "report": {
      "id": "report-id",
      "title": "Report Title",
      "description": "Report Description",
      "task_ids": ["task-id-1", "task-id-2"],
      "format": "pdf",
      "status": "generating",
      "created_at": "2025-05-10T11:00:00Z"
    }
  }
}
```

### System

#### Get System Status

```
GET /system/status
```

Retrieve system status information.

**Response:**

```json
{
  "status": "success",
  "message": "System status retrieved successfully",
  "data": {
    "status": {
      "cpu_usage": 32,
      "memory_usage": 45,
      "disk_usage": 28,
      "active_tasks": 1,
      "queued_tasks": 2,
      "uptime": 86400,
      "services": [
        {
          "name": "API Server",
          "status": "connected",
          "uptime": 86400
        },
        {
          "name": "Database",
          "status": "connected",
          "uptime": 86400
        },
        {
          "name": "Task Scheduler",
          "status": "connected",
          "uptime": 86400
        },
        {
          "name": "Scanner Engine",
          "status": "connected",
          "uptime": 86400
        }
      ],
      "timestamp": "2025-05-10T12:00:00Z"
    }
  }
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 400  | Bad Request - The request was malformed or contained invalid parameters |
| 401  | Unauthorized - Authentication is required or failed |
| 403  | Forbidden - The authenticated user does not have permission to access the resource |
| 404  | Not Found - The requested resource was not found |
| 405  | Method Not Allowed - The HTTP method is not supported for the resource |
| 429  | Too Many Requests - Rate limit exceeded |
| 500  | Internal Server Error - An unexpected error occurred on the server |

## Rate Limiting

The API implements rate limiting to prevent abuse. Rate limits are applied per API key or user.

Rate limit headers are included in API responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1620000000
```

If you exceed the rate limit, you will receive a 429 Too Many Requests response.

## Pagination

For endpoints that return lists of items, pagination is supported using the following query parameters:

- `page`: Page number (default: 1)
- `per_page`: Number of items per page (default: 20, max: 100)

Pagination information is included in the response:

```json
{
  "status": "success",
  "message": "Items retrieved successfully",
  "data": {
    "items": [...],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total_items": 45,
      "total_pages": 3
    }
  }
}
```

## Webhooks

SKrulll supports webhooks for event notifications. You can configure webhooks to receive notifications when certain events occur, such as task completion or vulnerability detection.

### Webhook Events

| Event | Description |
|-------|-------------|
| `task.created` | A new task has been created |
| `task.started` | A task has started execution |
| `task.completed` | A task has completed execution |
| `task.failed` | A task has failed |
| `vulnerability.detected` | A vulnerability has been detected |
| `report.generated` | A report has been generated |

### Webhook Payload

Webhook payloads follow a standard format:

```json
{
  "event": "task.completed",
  "timestamp": "2025-05-10T12:30:00Z",
  "data": {
    // Event-specific data
  }
}
```

### Configuring Webhooks

Webhooks can be configured through the web interface or API.

## API Clients

SKrulll provides official API clients for several programming languages:

- Python: [skrulll-python](https://github.com/pixelbrow720/skrulll-python)
- JavaScript: [skrulll-js](https://github.com/pixelbrow720/skrulll-js)

### Python Example

```python
from skrulll import SKrullClient

# Initialize client
client = SKrullClient(api_key="your-api-key", base_url="http://localhost:5000/api")

# Create a task
task = client.create_task(
    name="Domain Scan",
    module="osint.domain_recon",
    target="example.com",
    options={
        "whois": True,
        "dns": True,
        "subdomains": True
    }
)

# Get task status
status = client.get_task_status(task.id)

# Get task result when completed
if status.status == "completed":
    result = client.get_task(task.id)
    print(result.result)
```

### JavaScript Example

```javascript
const { SKrullClient } = require('skrulll-js');

// Initialize client
const client = new SKrullClient({
  apiKey: 'your-api-key',
  baseUrl: 'http://localhost:5000/api'
});

// Create a task
client.createTask({
  name: 'Domain Scan',
  module: 'osint.domain_recon',
  target: 'example.com',
  options: {
    whois: true,
    dns: true,
    subdomains: true
  }
})
.then(task => {
  console.log(`Task created with ID: ${task.id}`);
  
  // Poll for task completion
  const checkStatus = setInterval(() => {
    client.getTaskStatus(task.id)
      .then(status => {
        if (status.status === 'completed') {
          clearInterval(checkStatus);
          
          // Get task result
          client.getTask(task.id)
            .then(result => {
              console.log(result.result);
            });
        }
      });
  }, 5000);
});
```

## API Versioning

The API uses versioning to ensure backward compatibility. The current version is v1.

You can specify the API version in the URL:

```
https://your-skrulll-instance/api/v1/tasks
```

If no version is specified, the latest version is used.

## Support

If you encounter any issues with the API, please contact support at [pixelbrow13@gmail.com](mailto:pixelbrow13@gmail.com) or open an issue on GitHub.
