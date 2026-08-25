# Multi-Tenant Authorization Service

A production-grade RBAC engine for enforcing resource-level permissions across isolated tenant organizations.

## Overview

This service provides:

- **RBAC engine** with resource-level permissions per tenant organization
- **Full audit trail** of every authorization decision
- **Threat model** with implemented mitigations for session fixation, CSRF, token replay, IDOR based privilege escalation
- **Refresh token rotation** for enhanced security
- **Per-tenant rate limiting** on all auth endpoints

## Architecture

- Built with Go and PostgreSQL
- JWT/Sessions based authentication
- Documented threat model covering OWASP Top 10 vulnerabilities
- Self-run penetration testing verified

## Features

- Resource-level permission enforcement
- Isolated tenant organizations
- Complete audit logging
- Session fixation protection
- CSRF protection
- Token replay prevention
- IDOR protection
- Refresh token rotation
- Per-tenant rate limiting

## Technology Stack

- Go
- PostgreSQL
- JWT/Sessions
- Docker
- CI/CD

## Quick Start

```bash
# Clone the repository
git clone https://github.com/mcchukwu/multi-tenant-authorization-service.git

# Install dependencies
go mod tidy

# Run the service
make run
```

## Documentation

- [OpenAPI Specification](api/docs)
- [Threat Model](docs/threat-model.md)
- [API Documentation](api/)