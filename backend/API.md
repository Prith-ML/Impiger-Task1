# Address Book API

All endpoints require `Authorization: Bearer <access_token>` header.

**Get token:** Log in at http://localhost:8000, copy `access_token` from localStorage.  
**Refresh token:** `POST http://localhost:3000/api/auth/refresh` with `{ "refreshToken": "<your_refresh_token>" }`

---

## Endpoints

### List all contacts
`GET http://localhost:3000/api/contacts`

### Get one contact
`GET http://localhost:3000/api/contacts/:id`

### Create contact
`POST http://localhost:3000/api/contacts`  
Body (JSON):
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "555-1234",
  "address": "123 Main St"
}
```
`name` is required. Others optional.

### Update contact
`PUT http://localhost:3000/api/contacts/:id`  
Body (JSON):
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "555-1234",
  "address": "123 Main St"
}
```

### Delete contact
`DELETE http://localhost:3000/api/contacts/:id`
