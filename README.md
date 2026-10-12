# Policy Scanner GitHub App Backend

A FastAPI-based backend server for a GitHub App that automatically scans repositories for security policy violations in Docker, Kubernetes, and GitHub Actions workflows.

## Features

- **GitHub Webhook Integration**: Listens to push and pull request events
- **Multi-Scanner Support**: Runs Docker, Kubernetes, and GitHub Actions workflow security scans
- **MongoDB Storage**: Stores scan results organized by organization
- **RESTful API**: Provides endpoints to retrieve scan results
- **Background Processing**: Runs scans asynchronously to avoid blocking webhook responses
- **Docker Support**: Containerized application with Docker Compose

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GitHub App    │    │   FastAPI       │    │   MongoDB       │
│   Webhook       │───▶│   Backend       │───▶│   Database      │
│   Events        │    │   Server        │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Policy        │
                       │   Scanner       │
                       │   (Docker/K8s/  │
                       │    Workflow)    │
                       └─────────────────┘
```

## Tech Stack

- **Backend**: FastAPI (Python)
- **Database**: MongoDB
- **Containerization**: Docker & Docker Compose
- **Policy Engine**: Open Policy Agent (OPA)
- **Git Operations**: GitPython

## Quick Start

### Prerequisites

- Docker and Docker Compose
- GitHub App credentials (App ID, Private Key, Webhook Secret)

### 1. Clone the Repository

```bash
git clone <repository-url>
cd github-app-backend
```

### 2. Set Environment Variables

Copy the example environment file and configure it:

```bash
cp env.example .env
```

Edit `.env` with your GitHub App credentials:

```env
# GitHub App Configuration
GITHUB_APP_ID=your_github_app_id
GITHUB_APP_PRIVATE_KEY=your_github_app_private_key
GITHUB_WEBHOOK_SECRET=your_webhook_secret

# MongoDB Configuration
MONGODB_URL=mongodb://admin:password@localhost:27017/
DATABASE_NAME=policy_scanner

# Application Configuration
DEBUG=True
LOG_LEVEL=INFO
```

### 3. Start the Services

```bash
docker-compose up -d
```

This will start:
- FastAPI backend server on port 8000
- MongoDB database on port 27017
- Mongo Express (MongoDB UI) on port 8081

### 4. Verify Installation

Check if the services are running:

```bash
curl http://localhost:8000/health
```

You should see:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00"
}
```

## 📋 API Endpoints Overview

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/` | Root endpoint |
| GET | `/health` | Health check |
| POST | `/webhook/github` | GitHub webhook handler |
| POST | `/scan` | Manual scan trigger |
| GET | `/scans` | Get all scans with filtering |
| GET | `/scans/latest` | Get latest scan by org/repo/branch |
| GET | `/scans/{scan_id}` | Get specific scan by ID |
| GET | `/organizations` | Get all organizations |
| GET | `/organizations/{org_name}/repositories` | Get repositories for org |

---

## 📖 Detailed API Documentation

### 1. 🏠 **Root Endpoint**

**GET /** - Basic API status check

#### Request:
```bash
curl -X GET "http://localhost:8000/"
```

#### Response:
```json
{
  "message": "Policy Scanner API is running"
}
```

---

### 2. ❤️ **Health Check**

**GET /health** - Server health status

#### Request:
```bash
curl -X GET "http://localhost:8000/health"
```

#### Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:45.123456"
}
```

---

### 3. 🔍 **Manual Scan Trigger**

**POST /scan** - Trigger a manual security scan

#### Parameters:
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| org_name | string | Yes | - | GitHub organization name |
| repo_name | string | Yes | - | Repository name |
| installation_id | string| yes | installation_id of the app | 
| branch | string | No | "main" | Branch to scan |
| scan_type | string | No | "all" | Type of scan to run |

#### Request:
```bash
curl -X POST http://62.138.24.97:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "org_name": "MeetPatel2506",
    "repo_name": "app-demo",
    "branch": "main",
    "scan_type": "all",
    "installation_id": "82112168"
  }'

```

#### Response:
```json
{"message":"Scan initiated","org_name":"MeetPatel2506","repo_name":"app-demo","branch":"main","scan_type":"all","installation_id":"82112168"}

```

---

### 4. 📊 **Get All Scans**

**GET /scans** - Retrieve scans with optional filtering

#### Query Parameters:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| org_name | string | No | Filter by organization |
| repo_name | string | No | Filter by repository |
| limit | integer | No | Limit number of results (default: 50) |

#### Examples:

**Get all scans:**
```bash
curl -X GET "http://localhost:8000/scans"
```

**Filter by organization:**
```bash
curl -X GET "http://localhost:8000/scans?org_name=MeetPatel2506"
```

**Filter by org and repo:**
```bash
curl -X GET "http://localhost:8000/scans?org_name=MeetPatel2506&repo_name=app-demo"
```

**Limit results:**
```bash
curl -X GET "http://localhost:8000/scans?limit=10"
```

#### Response:
```json
{
  "message": "Retrieved 5 scans",
  "total_count": 5,
  "scans": [
    {
      "_id": "507f1f77bcf86cd799439011",
      "scan_id": "scan_20241206_143022_MeetPatel2506_app-demo",
      "scan_status": "completed",
      "created_at": "2024-12-06T14:30:22",
      "completed_at": "2024-12-06T14:35:45",
      "installation_id": "12345",
      "scan_metadata": {
        "scan_id": "scan_20241206_143022_MeetPatel2506_app-demo",
        "organization": "MeetPatel2506",
        "repository": "app-demo",
        "branch": "main",
        "commit_hash": "abc123def456",
        "commit_message": "Add new feature",
        "commit_author": "Meet Patel",
        "scan_type": "all",
        "scan_timestamp": "2024-12-06T14:35:45.123Z",
        "commit_date": "2024-12-06T14:29:45",
        "repository_url": "https://github.com/MeetPatel2506/app-demo.git",
        "event_type": "push"
      },
      "scan_results": {
        "scan_results": {
          "summary": {
            "total_issues": 5,
            "critical": 1,
            "high": 2,
            "medium": 2,
            "low": 0
          },
          "details": "..."
        }
      },
      "error": ""
    }
  ]
}
```

---

### 5. 🏆 **Get Latest Scan**

**GET /scans/latest** - Get the most recent scan for specific org/repo/branch

#### Query Parameters:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| org_name | string | Yes | Organization name |
| repo_name | string | Yes | Repository name |
| branch | string | Yes | Branch name |

#### Request:
```bash
curl -X GET "http://localhost:8000/scans/latest?org_name=MeetPatel2506&repo_name=app-demo&branch=main"
```

#### Success Response:
```json
{
  "message": "Latest scan retrieved successfully",
  "query": {
    "organization": "MeetPatel2506",
    "repository": "app-demo",
    "branch": "main"
  },
  "scan": {
    "_id": "507f1f77bcf86cd799439011",
    "scan_id": "scan_20241206_143022_MeetPatel2506_app-demo",
    "scan_status": "completed",
    "created_at": "2024-12-06T14:30:22",
    "completed_at": "2024-12-06T14:35:45",
    "installation_id": "12345",
    "scan_metadata": {
      "scan_id": "scan_20241206_143022_MeetPatel2506_app-demo",
      "organization": "MeetPatel2506",
      "repository": "app-demo",
      "branch": "main",
      "commit_hash": "abc123def456",
      "commit_message": "Add new feature",
      "commit_author": "Meet Patel",
      "scan_type": "all",
      "scan_timestamp": "2024-12-06T14:35:45.123Z",
      "commit_date": "2024-12-06T14:29:45",
      "repository_url": "https://github.com/MeetPatel2506/app-demo.git",
      "event_type": "push"
    },
    "scan_results": {
      "scan_results": {
        "summary": {
          "total_issues": 5,
          "critical": 1,
          "high": 2,
          "medium": 2,
          "low": 0
        },
        "details": "..."
      }
    },
    "error": ""
  }
}
```

#### Error Response (404):
```json
{
  "detail": "No scans found for organization 'MeetPatel2506', repository 'app-demo', branch 'feature-branch'"
}
```

---

### 6. 🔍 **Get Specific Scan**

**GET /scans/{scan_id}** - Get scan by specific scan ID

#### Path Parameters:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| scan_id | string | Yes | Unique scan identifier |

#### Request:
```bash
curl -X GET "http://localhost:8000/scans/scan_20241206_143022_MeetPatel2506_app-demo"
```

#### Success Response:
```json
{
  "_id": "507f1f77bcf86cd799439011",
  "scan_id": "scan_20241206_143022_MeetPatel2506_app-demo",
  "scan_status": "completed",
  "created_at": "2024-12-06T14:30:22",
  "completed_at": "2024-12-06T14:35:45",
  "installation_id": "12345",
  "scan_metadata": {
    "scan_id": "scan_20241206_143022_MeetPatel2506_app-demo",
    "organization": "MeetPatel2506",
    "repository": "app-demo",
    "branch": "main",
    "commit_hash": "abc123def456",
    "commit_message": "Add new feature",
    "commit_author": "Meet Patel",
    "scan_type": "all",
    "scan_timestamp": "2024-12-06T14:35:45.123Z",
    "commit_date": "2024-12-06T14:29:45",
    "repository_url": "https://github.com/MeetPatel2506/app-demo.git",
    "event_type": "push"
  },
  "scan_results": {
    "scan_results": {
      "summary": {
        "total_issues": 5,
        "critical": 1,
        "high": 2,
        "medium": 2,
        "low": 0
      },
      "details": "..."
    }
  },
  "error": ""
}
```

#### Error Response (404):
```json
{
  "detail": "Scan not found with ID: invalid_scan_id"
}
```

---

### 7. 🏢 **Get Organizations**

**GET /organizations** - Get list of all organizations that have been scanned

#### Request:
```bash
curl -X GET "http://localhost:8000/organizations"
```

#### Response:
```json
{
  "organizations": [
    "MeetPatel2506",
    "AnotherOrg",
    "TestOrg"
  ]
}
```

---

### 8. 📁 **Get Organization Repositories**

**GET /organizations/{org_name}/repositories** - Get repositories for specific organization

#### Path Parameters:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| org_name | string | Yes | Organization name |

#### Request:
```bash
curl -X GET "http://localhost:8000/organizations/MeetPatel2506/repositories"
```

#### Response:
```json
{
  "organization": "MeetPatel2506",
  "repositories": [
    "app-demo",
    "backend-server",
    "frontend-app",
    "mobile-app"
  ]
}
```

---

### 9. 🔗 **GitHub Webhook Handler**

**POST /webhook/github** - Handle GitHub webhook events (push, pull_request)

#### Headers:
| Header | Required | Description |
|--------|----------|-------------|
| X-GitHub-Event | Yes | Event type (push, pull_request) |
| X-Hub-Signature-256 | No* | Webhook signature (*if webhook secret is configured) |
| Content-Type | Yes | application/json |

#### Push Event Example:
```bash
curl -X POST "http://localhost:8000/webhook/github" \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature-256: sha256=your_signature_here" \
  -d '{
    "ref": "refs/heads/feature-branch",
    "repository": {
      "name": "app-demo",
      "owner": {
        "login": "MeetPatel2506"
      },
      "clone_url": "https://github.com/MeetPatel2506/app-demo.git"
    },
    "installation": {
      "id": 12345
    }
  }'
```

#### Pull Request Event Example:
```bash
curl -X POST "http://localhost:8000/webhook/github" \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: sha256=your_signature_here" \
  -d '{
    "pull_request": {
      "head": {
        "ref": "feature-branch"
      }
    },
    "repository": {
      "name": "app-demo",
      "owner": {
        "login": "MeetPatel2506"
      },
      "clone_url": "https://github.com/MeetPatel2506/app-demo.git"
    },
    "installation": {
      "id": 12345
    }
  }'
```

#### Response:
```json
{
  "message": "Scan initiated",
  "org_name": "MeetPatel2506",
  "repo_name": "app-demo",
  "branch": "feature-branch",
  "event_type": "push"
}
```

## MongoDB UI (Mongo Express)

The application includes Mongo Express, a web-based MongoDB admin interface for developers to view and manage the database.

### Accessing Mongo Express

1. Start the services:
   ```bash
   docker-compose up -d
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:8081
   ```

3. Login with the following credentials:
   - **Username**: `admin`
   - **Password**: `admin123`

### Features

- **Database Browser**: View all databases and collections
- **Document Viewer**: Browse and search scan results
- **Query Interface**: Run MongoDB queries directly
- **Data Export**: Export data in various formats
- **Real-time Updates**: See data changes in real-time

### Database Structure

The main database is `policy_scanner` with the following collections:
- `scans`: Contains all scan results
- `organizations`: Organization metadata
- `repositories`: Repository information

## GitHub App Setup

### 1. Create a GitHub App

1. Go to GitHub Settings → Developer settings → GitHub Apps
2. Click "New GitHub App"
3. Configure the app:
   - **App name**: Policy Scanner
   - **Homepage URL**: Your backend URL
   - **Webhook URL**: `http://your-domain.com/webhook/github`
   - **Webhook secret**: Generate a secure secret

### 2. Set Permissions

Configure the following permissions:
- **Repository permissions**:
  - Contents: Read
  - Metadata: Read
  - Pull requests: Read

### 3. Subscribe to Events

Subscribe to:
- Push
- Pull request

### 4. Install the App

1. Generate a private key for the app
2. Install the app on your repositories
3. Update your `.env` file with the credentials

## Scan Types

The backend supports three types of security scans:

### 1. Docker Security Scan
- Scans Dockerfiles for security best practices
- Checks for privileged mode, latest tags, secrets in ENV, etc.
- Uses OPA policies for validation

### 2. Kubernetes Security Scan
- Scans Kubernetes YAML manifests
- Checks for privileged containers, latest images, security contexts, etc.
- Validates against Kubernetes security policies

### 3. GitHub Actions Workflow Scan
- Scans `.github/workflows/` and `.github/actions/` directories
- Checks for security best practices in workflows
- Validates against workflow security policies

## Database Schema

### Scan Results Collection

```json
{
  "_id": "ObjectId",
  "scan_id": "scan_20240101_120000_org_repo",
  "org_name": "organization-name",
  "repo_name": "repository-name",
  "repo_url": "https://github.com/org/repo.git",
  "branch": "main",
  "scan_type": "all",
  "scan_status": "completed|running|failed",
  "created_at": "2024-01-01T12:00:00Z",
  "completed_at": "2024-01-01T12:05:00Z",
  "findings": {
    "scan_report": {
      "metadata": {...},
      "summary": {...},
      "Workflow-findings": [...],
      "kubernetes-findings": [...],
      "docker-findings": [...]
    }
  },
  "error": "error message if failed"
}
```

## Development

### Local Development Setup

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Start MongoDB locally or use Docker:
```bash
docker run -d -p 27017:27017 --name mongodb mongo:7.0
```

3. Run the FastAPI server:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Testing

```bash
# Run tests (if available)
pytest

# Test API endpoints
curl http://localhost:8000/docs  # Swagger UI
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_APP_ID` | GitHub App ID | Required |
| `GITHUB_APP_PRIVATE_KEY` | GitHub App private key | Required |
| `GITHUB_WEBHOOK_SECRET` | Webhook secret for verification | Required |
| `MONGODB_URL` | MongoDB connection string | `mongodb://admin:password@localhost:27017/` |
| `DATABASE_NAME` | MongoDB database name | `policy_scanner` |
| `DEBUG` | Enable debug mode | `True` |
| `LOG_LEVEL` | Logging level | `INFO` |

### Docker Configuration

The application uses Docker Compose with two services:

- **app**: FastAPI backend server
- **mongo**: MongoDB database

Volumes are mounted for:
- Repository storage: `./repos:/app/repos`
- Output storage: `./output:/app/output`
- MongoDB data: `mongodb_data:/data/db`

## Monitoring and Logs

### View Logs

```bash
# View all service logs
docker-compose logs

# View specific service logs
docker-compose logs app
docker-compose logs mongo

# Follow logs in real-time
docker-compose logs -f app
```

### Health Monitoring

The `/health` endpoint provides basic health status. For production, consider adding:

- Prometheus metrics
- Application performance monitoring
- Database connection monitoring
- Disk space monitoring

## Security Considerations

1. **Webhook Verification**: All GitHub webhooks are verified using HMAC signatures
2. **Environment Variables**: Sensitive data is stored in environment variables
3. **Repository Cleanup**: Cloned repositories are automatically cleaned up after scanning
4. **Database Security**: MongoDB is configured with authentication
5. **Network Security**: Consider using reverse proxy and SSL termination in production

## Troubleshooting

### Common Issues

1. **Webhook Verification Failed**
   - Check `GITHUB_WEBHOOK_SECRET` environment variable
   - Verify webhook URL is accessible

2. **MongoDB Connection Failed**
   - Check MongoDB service is running
   - Verify connection string in environment variables

3. **Scan Failures**
   - Check repository access permissions
   - Verify OPA is installed and working
   - Check disk space for repository cloning

4. **Permission Denied**
   - Ensure GitHub App has required permissions
   - Check repository installation status

### Debug Mode

Enable debug mode for detailed logging:

```bash
export DEBUG=True
export LOG_LEVEL=DEBUG
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your license information here]

## Support

For issues and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the API documentation at `/docs`
