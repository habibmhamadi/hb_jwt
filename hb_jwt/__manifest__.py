# -*- coding: utf-8 -*-
{
    'name': "JWT Authentication",

    'summary': "Secure API authentication with access tokens and refresh token rotation",
    'description': """
JWT Authentication Module for Odoo 17.0+
=====================================

Provides complete JWT (JSON Web Token) authentication system for Odoo APIs.

Key Features:
- Industry-standard JWT authentication with HS256 signing
- Refresh token rotation with automatic revocation
- Password change detection to invalidate tokens
- Protected API endpoints with Bearer token validation
- Complete token management with audit trails

API Endpoints:
- POST /api/auth/login: Authenticate and get tokens
- POST /api/auth/refresh: Rotate refresh token
- POST /api/auth/logout: Revoke specific token
- POST /api/auth/logout_all: Revoke all user tokens
- GET /api/me: Get authenticated user info

Installation:
1. Install PyJWT: pip install PyJWT
2. Install this module in Odoo
3. Configure system parameters as needed

Configuration via system parameters:
- jwt.secret: JWT signing secret
- jwt.ttl_seconds: Access token lifetime (default: 1296000)
- jwt.refresh_ttl_days: Refresh token lifetime (default: 30)
""",

    'author': "Habib Mhamadi",
    'website': "https://github.com/habibmhamadi/hb_jwt",

    'category': 'Technical',
    'version': '17.0.1.0.0',
    'license': 'LGPL-3',

    'depends': ['base'],

    'data': [
        'security/ir.model.access.csv',
    ],

    'images': ['static/description/banner.png'],

    'external_dependencies': {
        'python': ['PyJWT'],
    },

    'installable': True,
    'application': False,
    'auto_install': False,
}
