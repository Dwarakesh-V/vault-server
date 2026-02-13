# Password Manager Vault - Server

A secure, zero-knowledge password manager vault server with Multi-Factor Authentication (MFA) support.

## 🔒 Features

- **Zero-Knowledge Architecture**: All encryption happens client-side; the server never sees your master password or unencrypted data
- **Secure Authentication**: Uses SRP (Secure Remote Password) protocol with Argon2 key derivation
- **Multi-Factor Authentication (MFA)**: TOTP-based two-factor authentication using authenticator apps
- **QR Code Setup**: Easy MFA setup with automatic QR code generation
- **Backup Codes**: Recovery codes in case you lose access to your authenticator app
- **RESTful API**: Simple and secure API for the password and the vault operations

## 📋 Requirements

- Python 3.8+
- pip (Python package manager)

## 🚀 Installation

### 1. Clone or Navigate to the Project

```bash
cd vault-server
```

### 2. Create a Virtual Environment (Recommended)

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## ▶️ Running the Server

Start the FastAPI server using uvicorn:

```bash
uvicorn server.api:app --reload --host 0.0.0.0 --port 8000
```

The server will be available at `http://localhost:8000`

### API Documentation

Once the server is running, you can access:
- **Interactive API Docs**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

### Running with HTTPS (Secure)

To run the server securely with HTTPS/TLS (User Story 5.2):

1. **Generate SSL Certificates**:
   Run the utility script to generate `cert.pem` and `key.pem` for local development:
   ```bash
   python generate_cert.py
   ```

2. **Start the Secure Server**:
   Use the provided runner script:
   ```bash
   python run_server.py
   ```
   The server will be available at `https://localhost:8000`.
   
   **Note**: Your browser will likely show a warning about a self-signed certificate. This is expected for local development; you can proceed safely by clicking "Advanced" -> "Proceed to localhost (unsafe)".

## 🔐 Multi-Factor Authentication (MFA)

### Supported Authenticator Apps

This server uses **TOTP (Time-based One-Time Password)** standard, compatible with all major authenticator apps:

- **Google Authenticator** (iOS, Android)
- **Microsoft Authenticator** (iOS, Android)
- **Authy** (iOS, Android, Desktop)
- **1Password** (iOS, Android, Desktop)
- **Bitwarden Authenticator** (iOS, Android)
- **FreeOTP** (iOS, Android)
- **Any RFC 6238 compliant authenticator**

### MFA Setup Flow

#### 1. Register an Account
```http
POST /register
Content-Type: application/json

{
  "username": "youruser",
  "salt": "client_generated_salt",
  "verifier": "srp_verifier"
}
```

#### 2. Login to Get Token
```http
POST /login
Content-Type: application/json

{
  "username": "youruser",
  "verifier": "srp_verifier"
}
```

Response:
```json
{
  "token": "your_auth_token_here"
}
```

#### 3. Setup MFA (Authenticated)
```http
POST /mfa/setup
Authorization: your_auth_token_here
```

Response includes:
```json
{
  "secret": "BASE32_ENCODED_SECRET",
  "provisioning_uri": "otpauth://totp/...",
  "qr_code": "data:image/png;base64,...",
  "backup_codes": [
    "ABCD-EFGH",
    "IJKL-MNOP",
    "..."
  ]
}
```

**Important**: 
- Save your **backup codes** in a secure location
- Scan the QR code with your authenticator app
- The QR code is only shown once during setup

#### 4. Verify MFA Code
```http
POST /mfa/verify
Content-Type: application/json

{
  "username": "youruser",
  "code": "123456"
}
```

Enter the 6-digit code from your authenticator app to enable MFA.

#### 5. Login with MFA (After Enabled)
```http
POST /login/mfa
Content-Type: application/json

{
  "username": "youruser",
  "verifier": "srp_verifier",
  "mfa_code": "123456"
}
```

### Additional MFA Endpoints

#### Check MFA Status
```http
GET /mfa/status/{username}
```

Response:
```json
{
  "mfa_enabled": true
}
```

#### Disable MFA (Authenticated)
```http
POST /mfa/disable
Authorization: your_auth_token_here
```

Response:
```json
{
  "ok": true,
  "message": "MFA disabled successfully"
}
```

## 📖 API Reference

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/auth_salt/{username}` | Get salt for user | No |
| POST | `/register` | Register new user | No |
| POST | `/login` | Login without MFA | No |
| POST | `/login/mfa` | Login with MFA | No |

### Vault Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/vault` | Get encrypted vault | Yes |
| POST | `/vault` | Store encrypted vault | Yes |

### MFA Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/mfa/status/{username}` | Check if MFA enabled | No |
| POST | `/mfa/setup` | Setup MFA (get QR code) | Yes |
| POST | `/mfa/verify` | Verify and enable MFA | No |
| POST | `/mfa/disable` | Disable MFA | Yes |

## 🔧 Configuration

### Security Features (User Stories 5.5 & 5.6)

The server now tracks failed login attempts and blocks IPs to prevent brute-force attacks.

#### Protected Endpoints
- `/register`
- `/login`
- `/mfa/verify`
- `/login/mfa`

#### Rate Limits
- **Threshold**: 5 failed attempts within 5 minutes.
- **Block Duration**: 1 minute (Test Mode) / 15 minutes (Production).

#### API Behavior - Frontend Integration
When an IP is blocked, the API returns:
- **Status Code**: `429 Too Many Requests`
- **Response Body**:
  ```json
  {
    "detail": "IP blocked due to too many failed attempts. Try again in 59 seconds."
  }
  ```

**Frontend Requirements:**
1.  Check for `429` status code on login/register failures.
2.  Display the error message from `detail` to the user so they know why they are blocked and when to try again.

### Security Settings

The server uses the following security configurations:

- **Password Hashing**: Argon2 (client-side)
- **Key Derivation**: PBKDF2 or Argon2 (client-side)
- **Encryption**: NaCl/libsodium (client-side)
- **MFA**: TOTP with 30-second window
- **Session Tokens**: 64-character hex tokens

### File Storage

- **Auth Database**: `server/auth_db.json` (stores user credentials and MFA secrets)
- **Vault Data**: `server/data/{username}.json` (stores encrypted vault blobs)

**⚠️ Security Note**: In production, use proper database systems and secure secret storage (e.g., HashiCorp Vault, AWS Secrets Manager)

## 🛡️ Security Best Practices

### Server-Side
1. **Never log sensitive data** (passwords, tokens, MFA secrets)
2. **Use HTTPS** in production
3. **Set up rate limiting** to prevent brute force attacks
4. **Use secure session storage** (Redis, database)
5. **Implement proper CORS** policies
6. **Regular security updates** for all dependencies

### Client-Side
1. **Never send master password** to server
2. **Encrypt all data before sending** to server
3. **Derive encryption keys locally** using strong KDF
4. **Clear sensitive data** from memory after use
5. **Implement proper key stretching** (Argon2, PBKDF2)

### MFA Best Practices
1. **Save backup codes** immediately after setup
2. **Store backup codes securely** (offline, encrypted)
3. **Don't share MFA secrets** or QR codes
4. **Use time-synced devices** for accurate TOTP codes
5. **Have recovery plan** in case of device loss

## 🧪 Testing

### Manual Testing with cURL

**Register a user:**
```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","salt":"somesalt","verifier":"someverifier"}'
```

**Login:**
```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","verifier":"someverifier"}'
```

**Setup MFA:**
```bash
curl -X POST http://localhost:8000/mfa/setup \
  -H "Authorization: YOUR_TOKEN_HERE"
```

## 📂 Project Structure

```
vault-server/
├── server/
│   ├── api.py          # FastAPI application and routes
│   ├── auth.py         # Authentication and MFA logic
│   ├── storage.py      # Vault data storage
│   ├── auth_db.json    # User credentials database
│   └── data/           # Encrypted vault storage
├── requirements.txt    # Python dependencies
├── ctest.py           # Test script
└── README.md          # This file
```

## 🐛 Troubleshooting

### Common Issues

**1. "Invalid MFA code" errors**
- Ensure your device time is synced correctly
- TOTP codes are time-based and expire every 30 seconds
- Try the next code if current one expires

**2. Lost authenticator device**
- Use backup codes to login
- Contact admin to disable MFA if backup codes are lost
- Re-setup MFA after regaining access

**3. QR code not scanning**
- Ensure adequate screen brightness
- Try manually entering the secret key instead
- Verify authenticator app supports TOTP

**4. Server not starting**
- Check if port 8000 is available
- Verify all dependencies are installed
- Check Python version (3.8+ required)

## 📝 License

This is a educational/demonstration project. Use at your own risk in production environments.

## 🤝 Contributing

This is a course project for Software Engineering. 

## ⚠️ Disclaimer

This server is designed for educational purposes. For production use:
- Implement proper database systems
- Add comprehensive logging and monitoring
- Use professional secret management
- Implement rate limiting and DDoS protection
- Regular security audits
- Compliance with data protection regulations

## 📞 Support

For issues related to MFA setup or usage, refer to:
- Your authenticator app's documentation
- [RFC 6238 - TOTP Specification](https://tools.ietf.org/html/rfc6238)
- FastAPI documentation: https://fastapi.tiangolo.com/
