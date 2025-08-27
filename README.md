# E2E Encrypted Messaging Application

A real-time messaging application with end-to-end encryption using RSA-OAEP + AES-GCM hybrid cryptography and message authentication via RSA-PSS digital signatures.

## Features

- End-to-end encrypted messaging between users
- Digital signatures for message authenticity and integrity
- Real-time communication via WebSocket
- Persistent encryption keys across browser sessions
- User authentication with JWT tokens
- Contact list and online status indicators
- Typing indicators

## Security Architecture

### Cryptographic Scheme
The application uses a combination of cryptographic primitives for confidentiality and authenticity:

For **Encryption (Confidentiality)**: A hybrid cryptosystem combining:
- **RSA-OAEP (2048-bit)** for secure key exchange.
- **AES-GCM (256-bit)** for efficient message content encryption.
For **Authentication (Authenticity & Integrity)**:
- **RSA-PSS (2048-bit)** for generating and verifying digital signatures.
- **SHA-256** as the underlying hash algorithm for PSS.

### Message Flow
1. **Key Generation**: Each user generates two RSA key pairs (2048-bit):
   - One pair for encryption/decryption (RSA-OAEP).
   - One pair for signing/verification (RSA-PSS).
2. **Message Signing and Encryption**: 
   - Create a cleartext payload containing the message content, sender ID, receiver ID, and a precise timestamp.
   - Sign this payload using the sender's signing private key to create a digital signature.
   - Generate a random, single-use AES-256 key.
   - Encrypt only the message content with this AES-GCM key.
   - Encrypt the AES key with the recipient's encryption public key (RSA-OAEP).
   - Send the encrypted content, encrypted AES key, the signature, and the signing timestamp to the server.
3. **Message Decryption**:
   - Decrypt the AES key using the recipient's encryption private key.
   - Use the decrypted AES key to decrypt the message content.
   - Reconstruct the original payload using the now-decrypted content and other data from the message (sender ID, receiver ID, timestamp).
   - Fetch the sender's signing public key from the server.
   - Verify the received signature against the reconstructed payload.
   - If the signature is valid, display the message. If it is invalid, the message is considered tampered with and is discarded.

### Key Persistence
- **Private keys**: Stored in browser localStorage with user-specific naming (`privateKey_${userId}`)
- **Signing keys**: Stored similarly in localStorage (signingPrivateKey_${userId}).
- **Public keys**: Stored both locally and on the server for sharing
- **Key lifecycle**: Keys persist across logout/login cycles within the same browser
- **Cross-browser behavior**: Different browsers generate separate key pairs (expected E2E behavior)

### Security Properties
- **Confidentiality**: Only intended recipients can decrypt messages
- **Integrity**: AES-GCM provides authenticated encryption for the content, and the digital signature ensures the integrity of the entire message payload
- **Authenticity**: Digital signatures ensure that messages originate from the claimed sender.
- **Non-repudiation** (Partial): The sender cannot easily deny sending a message they have signed, as long as their signing private key is not compromised.
- **Key Verification**: No public key fingerprint verification implemented
- **Forward Secrecy**: Not implemented (messages remain decryptable if keys are compromised)

## Important Security Notes

### Key Management
- Private keys are stored in browser localStorage
- Keys are user-specific and browser-specific
- Logging out does NOT clear encryption keys (by design)
- Cross-browser sessions require new key generation

### Message Decryption Behavior
- Users can only decrypt messages intended for them
- Messages with an invalid signature are discarded and not shown to the user.
- Messages sent by a user show as "[Encrypted message you sent]"
- Messages encrypted with old/different keys show appropriate error messages
- Different browsers cannot decrypt each other's messages (expected E2E behavior)

### Limitations
- No forward secrecy implementation
- No key rotation mechanism
- No public key fingerprint verification
- Keys stored in localStorage are vulnerable to XSS attacks
- No message delivery confirmation system

### Testing Multi-User Scenarios
- Use different browsers for different users
- Test logout/login cycles
- Verify message decryption works correctly
- Test key persistence across browser refreshes

### Common Issues
- **"Message encrypted with different keys"**: Expected when keys don't match
- **Failed decryption**: Usually indicates key mismatch or corrupted data
- **Authentication issues**: Clear localStorage and try fresh login

## Project Structure

```
├── server.js                 # Express server with Socket.IO
├── public/
│   ├── index.html            # Main application interface
│   ├── css/style.css         # Application styles
│   └── js/
│       ├── app.js            # Main application logic
│       └── crypto.js         # E2E encryption implementation
└── messaging.db              # SQLite database (auto-created)
```

## Setup and Installation

### Prerequisites
- Node.js (v14 or higher)
- npm

### Installation
```bash
git clone <repository-url>
cd E2E-Encrypted-Messaging-App
npm install
```

### Environment Configuration
```bash
# Create .env file (JWT_SECRET will be auto-generated if not provided)
touch .env
```

### Running the Application
```bash
npm start
# or
node server.js
```

The application will be available at `http://localhost:3000`

## Database Schema

### Users Table
- `id`: Unique user identifier (UUID)
- `username`: Unique username
- `password_hash`: Bcrypt hashed password
- `public_key`: Base64 encoded RSA public key
- `signing_public_key`: Base64 encoded RSA-PSS public key (for verification)
- `refresh_token`: JWT refresh token
- `created_at`: Account creation timestamp

### Messages Table
- `id`: Unique message identifier
- `sender_id`: Foreign key to users table
- `receiver_id`: Foreign key to users table
- `encrypted_content`: JSON string containing encrypted message data
- `signature`: The digital signature of the message payload
- `signing_timestamp`: The timestamp used in the signature payload
- `sig_algo`: The signature algorithm used (e.g., 'RSA-PSS')
- `timestamp`: Message creation time

## API Endpoints

### Authentication
- `POST /api/register` - User registration
- `POST /api/login` - User login

### Users
- `GET /api/users` - Get contact list
- `GET /api/users/:username/publickey` - Get user's public key
- `GET /api/user/:username/signingkey` - Get user's signing public key
- `PUT /api/user/publickey` - Update user's public key

### Messages
- `GET /api/messages/:userId` - Get message history with specific user

## WebSocket Events

### Client to Server
- `authenticate` - Authenticate socket connection
- `private_message` - Send encrypted message
- `typing_start/typing_stop` - Typing indicators

### Server to Client
- `authenticated` - Authentication confirmation
- `new_message` - Receive encrypted message
- `user_online/user_offline` - User status updates
- `user_typing/user_stopped_typing` - Typing indicators




