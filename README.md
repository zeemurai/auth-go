# Auth Service in Go

This is a secure authentication service implemented in Go that provides a two-step login process with email OTP verification.

## Features

- Two-step authentication with email OTP
- Account locking after multiple failed attempts
- Password validation
- Email verification for new accounts
- JWT token generation
- MongoDB integration
- Rate limiting and security features

## Prerequisites

- Go 1.21 or higher
- MongoDB
- SMTP server for sending emails

## Setup

1. Clone the repository
2. Copy `.env.example` to `.env` and update the values:
   ```bash
   cp .env.example .env
   ```
3. Install dependencies:
   ```bash
   go mod download
   ```
4. Build the application:
   ```bash
   go build -o auth-service ./cmd/main.go
   ```

## Running the Service

```bash
./auth-service
```

The service will start on the port specified in your `.env` file (default: 8080).

## API Endpoints

### 1. Login (First Step)

```http
POST /api/login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "yourpassword"
}
```

### 2. Verify Login (Second Step)

```http
POST /api/login/verify
Content-Type: application/json

{
    "email": "user@example.com",
    "otp": "123456"
}
```

## Security Features

- Password hashing using bcrypt
- JWT for session management
- Account locking after 5 failed attempts (15-minute lockout)
- OTP expiration after 5 minutes
- Email verification for new accounts
- Secure password requirements (minimum 8 characters)

## Error Handling

The service provides detailed error messages for:

- Invalid credentials
- Account lockout
- OTP expiration
- Email verification requirements
- Rate limiting
- Server errors

## Environment Variables

- `PORT`: Server port (default: 8080)
- `MONGODB_URI`: MongoDB connection string
- `MONGODB_DB`: Database name
- `JWT_SECRET_KEY`: Secret key for JWT signing
- `SMTP_HOST`: SMTP server host
- `SMTP_PORT`: SMTP server port
- `SMTP_USER`: SMTP username
- `SMTP_PASS`: SMTP password
- `FROM_EMAIL`: Sender email address
