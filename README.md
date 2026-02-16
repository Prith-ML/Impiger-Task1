# OAuth 2.0 Authentication with Keycloak

Authentication system with OAuth 2.0, JWT tokens, Keycloak, and MailHog.

## Setup

1. Start services:
```bash
docker-compose up -d
```

2. Configure Keycloak (http://localhost:8080):
   - Login: admin/admin
   - Create realm: `myrealm`
   - Create client: `my-app`
   - Enable client authentication
   - Add redirect URI: `http://localhost:8000/*`
   - Copy client secret from Credentials tab
   - Update `KEYCLOAK_CLIENT_SECRET` in docker-compose.yml
   - Create user with password

3. Restart backend:
```bash
docker-compose restart backend
```

4. Access app: http://localhost:8000

## Services

- Frontend: http://localhost:8000
- Backend: http://localhost:3000
- Keycloak: http://localhost:8080
- MailHog: http://localhost:8025

## Features

- OAuth 2.0 Authorization Code Flow
- JWT token authentication
- Login/Logout with email notifications
- Protected API endpoints
