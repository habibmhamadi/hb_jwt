# JWT Authentication Module for Odoo 17.0+

Secure token-based authentication system for Odoo with access tokens and refresh token rotation.

## Overview

This module provides a complete JWT (JSON Web Token) authentication system for your Odoo instance, enabling secure API access for mobile apps, external integrations, and API-first architectures. Built with industry-standard security practices including token rotation, password change detection, and comprehensive audit trails.

## Features

### 🔐 Secure Token-Based Authentication
- **JWT-based authentication** with HS256 signing algorithm
- **Refresh token rotation** for enhanced security
- **Password change detection** that invalidates all existing tokens
- **Configurable token expiration** times

### 🔄 Complete Authentication Flow
- **Login endpoint** to obtain access and refresh tokens
- **Token refresh endpoint** with automatic rotation
- **Logout endpoints** for individual or all sessions
- **Protected API endpoints** with Bearer token validation

### 📊 Token Management
- **Database-backed refresh tokens** with full audit trail
- **User agent and IP tracking** for security monitoring
- **Automatic token revocation** on password changes
- **CORS support** out of the box

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Authenticate with credentials, returns access + refresh tokens |
| `/api/auth/refresh` | POST | Rotate refresh token and get new access token |
| `/api/auth/logout` | POST | Revoke a specific refresh token |
| `/api/auth/logout_all` | POST | Revoke all tokens for authenticated user |
| `/api/me` | GET | Get authenticated user information |

## Installation

### Requirements
- Odoo 17.0+
- PyJWT Python package

### Steps

1. Install PyJWT:
```bash
pip install PyJWT
```

2. Copy the module to your Odoo addons directory

3. Update the app list in Odoo

4. Install the "JWT Authentication" module

## Configuration

The module uses system parameters for configuration:

- `jwt.secret`: JWT signing secret (default: "mysecret!")
- `jwt.ttl_seconds`: Access token lifetime in seconds (default: 1296000 = 15 days)
- `jwt.refresh_ttl_days`: Refresh token lifetime in days (default: 30)

Set these via **Settings > Technical > Parameters > System Parameters**.

## Usage Example

### Login
```bash
curl -X POST https://your-odoo.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login":"admin","password":"admin"}'

Response:
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 1296000,
  "refresh_token": "...",
  "refresh_expires_in_days": 30,
  "user": {"id": 2, "login": "admin"}
}
```

### Access Protected Endpoint
```bash
curl -X GET https://your-odoo.com/api/me \
  -H "Authorization: Bearer <access_token>"
```

### Refresh Token
```bash
curl -X POST https://your-odoo.com/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

## Technical Details

**Author:** Habib Mhamadi  
**Website:** https://github.com/habibmhamadi/hb_jwt  
**License:** LGPL-3  
**Category:** Technical

## Security Features

- ✅ Token rotation on refresh (old tokens automatically revoked)
- ✅ Password change invalidation (tokens become invalid when password changes)
- ✅ Hashed refresh token storage in database
- ✅ Comprehensive token expiration checks
- ✅ User agent and IP address tracking
- ✅ Session revocation capabilities

## Repository

https://github.com/habibmhamadi/hb_jwt
