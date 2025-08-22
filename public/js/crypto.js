/**
 * E2E Encryption Handler
 * Manages RSA-OAEP + AES-GCM hybrid encryption for secure messaging
 */
class E2ECrypto {
    constructor() {
        this.keyPair = null;
        this.publicKeyCache = new Map();
    }

    /**
     * Initialize encryption keys for a specific user
     * @param {string} userId - User ID for key storage
     * @returns {Promise<Object|null>} Key pair or null
     */
    async initializeForUser(userId) {
        if (!userId) {
            throw new Error('User ID is required for key initialization');
        }

        // Try to load existing keys first
        try {
            await this.loadKeyPair(userId);
            if (this.keyPair) {
                console.log('✅ Loaded existing keys for user:', userId);
                return this.keyPair;
            }
        } catch (error) {
            console.warn('Failed to load existing keys:', error);
            this.clearKeys(userId);
        }
        
        console.log('🔑 Generating new encryption keys for user:', userId);
        this.showLoadingOverlay('Generating encryption keys...');
        try {
            await this.generateKeyPair(userId);
            console.log('✅ Generated new keys for user:', userId);
        } finally {
            this.hideLoadingOverlay();
        }
        
        return this.keyPair;
    }

    /**
     * Generate new RSA key pair for encryption
     * @param {string} userId - User ID for key storage
     * @returns {Promise<Object>} Generated key pair
     */
    async generateKeyPair(userId) {
        if (!window.crypto?.subtle) {
            throw new Error('Web Crypto API not available. Requires HTTPS or localhost.');
        }
        
        try {
            this.keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );
            
            if (userId) {
                await this.saveKeyPair(userId);
            }
            
            return this.keyPair;
        } catch (error) {
            throw new Error(`Key generation failed: ${error.message}`);
        }
    }

    /**
     * Save key pair to localStorage with user-specific naming
     * @param {string} userId - User ID for key storage
     * @returns {Promise<boolean>} Success status
     */
    async saveKeyPair(userId) {
        if (!this.keyPair || !userId) {
            return false;
        }
        
        try {
            const exportedPrivate = await window.crypto.subtle.exportKey(
                "pkcs8", 
                this.keyPair.privateKey
            );
            
            const exportedPublic = await window.crypto.subtle.exportKey(
                "spki", 
                this.keyPair.publicKey
            );
            
            localStorage.setItem(`privateKey_${userId}`, this.arrayBufferToBase64(exportedPrivate));
            localStorage.setItem(`publicKey_${userId}`, this.arrayBufferToBase64(exportedPublic));
            
            return true;
        } catch (error) {
            throw new Error(`Failed to save keys: ${error.message}`);
        }
    }

    /**
     * Load key pair from localStorage
     * @param {string} userId - User ID for key retrieval
     * @returns {Promise<Object|null>} Key pair or null if not found
     */
    async loadKeyPair(userId) {
        if (!userId) {
            return null;
        }
        
        try {
            const privateKeyBase64 = localStorage.getItem(`privateKey_${userId}`);
            const publicKeyBase64 = localStorage.getItem(`publicKey_${userId}`);
            
            if (!privateKeyBase64 || !publicKeyBase64) {
                return null;
            }
            
            const privateKey = await window.crypto.subtle.importKey(
                "pkcs8",
                this.base64ToArrayBuffer(privateKeyBase64),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                true,
                ["decrypt"]
            );
            
            const publicKey = await window.crypto.subtle.importKey(
                "spki",
                this.base64ToArrayBuffer(publicKeyBase64),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                true,
                ["encrypt"]
            );
            
            this.keyPair = { publicKey, privateKey };
            return this.keyPair;
        } catch (error) {
            if (userId) {
                localStorage.removeItem(`privateKey_${userId}`);
                localStorage.removeItem(`publicKey_${userId}`);
            }
            return null;
        }
    }

    /**
     * Clear stored keys and reset crypto state
     * @param {string} userId - Optional user ID to clear specific keys
     */
    clearKeys(userId) {
        if (userId) {
            localStorage.removeItem(`privateKey_${userId}`);
            localStorage.removeItem(`publicKey_${userId}`);
        } else {
            // Clear all crypto-related data
            const keys = Object.keys(localStorage);
            keys.forEach(key => {
                if (key.startsWith('privateKey_') || key.startsWith('publicKey_')) {
                    localStorage.removeItem(key);
                }
            });
        }
        
        this.keyPair = null;
        this.publicKeyCache.clear();
    }

    /**
     * Export public key as base64 string
     * @returns {Promise<string>} Base64 encoded public key
     */
    async exportPublicKey() {
        if (!this.keyPair?.publicKey) {
            throw new Error('No key pair available for export');
        }

        try {
            const exported = await window.crypto.subtle.exportKey("spki", this.keyPair.publicKey);
            return this.arrayBufferToBase64(exported);
        } catch (error) {
            throw new Error(`Failed to export public key: ${error.message}`);
        }
    }

    /**
     * Import public key from base64 string
     * @param {string} publicKeyBase64 - Base64 encoded public key
     * @returns {Promise<CryptoKey>} Imported public key
     */
    async importPublicKey(publicKeyBase64) {
        // Check cache first
        if (this.publicKeyCache.has(publicKeyBase64)) {
            return this.publicKeyCache.get(publicKeyBase64);
        }

        try {
            const publicKey = await window.crypto.subtle.importKey(
                "spki",
                this.base64ToArrayBuffer(publicKeyBase64),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                false,
                ["encrypt"]
            );

            this.publicKeyCache.set(publicKeyBase64, publicKey);
            return publicKey;
        } catch (error) {
            throw new Error(`Failed to import public key: ${error.message}`);
        }
    }

    /**
     * Encrypt message using hybrid RSA-OAEP + AES-GCM encryption
     * @param {string} message - Plain text message
     * @param {string} recipientPublicKeyBase64 - Recipient's public key
     * @returns {Promise<string>} Encrypted message as JSON string
     */
    async encryptMessage(message, recipientPublicKeyBase64) {
        try {
            let publicKey = this.publicKeyCache.get(recipientPublicKeyBase64);
            if (!publicKey) {
                publicKey = await this.importPublicKey(recipientPublicKeyBase64);
                this.publicKeyCache.set(recipientPublicKeyBase64, publicKey);
            }

            const encoder = new TextEncoder();
            const messageBuffer = encoder.encode(message);
            const aesKey = await window.crypto.subtle.generateKey(
                {
                    name: "AES-GCM",
                    length: 256
                },
                true,
                ["encrypt", "decrypt"]
            );

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encryptedMessage = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                aesKey,
                messageBuffer
            );

            const exportedAESKey = await window.crypto.subtle.exportKey("raw", aesKey);
            const encryptedAESKey = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP"
                },
                publicKey,
                exportedAESKey
            );

            const result = {
                encryptedAESKey: this.arrayBufferToBase64(encryptedAESKey),
                encryptedContent: this.arrayBufferToBase64(encryptedMessage),
                iv: this.arrayBufferToBase64(iv)
            };

            return JSON.stringify(result);
        } catch (error) {
            console.error('Error encrypting message:', error);
            throw error;
        }
    }

    /**
     * Decrypt message using hybrid RSA-OAEP + AES-GCM decryption
     * @param {string} encryptedData - Encrypted message as JSON string
     * @returns {Promise<string>} Decrypted plain text message
     */
   async decryptMessage(encryptedData) {

    if (!this.keyPair || !this.keyPair.privateKey) {
        throw new Error('Key pair not available');
    }
    
    try {
        const data = JSON.parse(encryptedData);
        const encryptedAESKey = this.base64ToArrayBuffer(data.encryptedAESKey);
        
        const aesKeyBuffer = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            this.keyPair.privateKey,
            encryptedAESKey
        );
        
        const aesKey = await window.crypto.subtle.importKey(
            "raw",
            aesKeyBuffer,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );
        
        const encryptedContent = this.base64ToArrayBuffer(data.encryptedContent);
        const iv = this.base64ToArrayBuffer(data.iv);
        
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            aesKey,
            encryptedContent
        );
        
        return new TextDecoder().decode(decryptedBuffer);
    } catch (error) {
        throw error;
    }
}

    // Helper methods
    showLoadingOverlay(text = 'Loading...') {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.style.display = 'flex';
            const textElement = overlay.querySelector('p');
            if (textElement) textElement.textContent = text;
        }
    }

    hideLoadingOverlay() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) overlay.style.display = 'none';
    }

    /**
     * Convert ArrayBuffer to Base64 string
     */
    arrayBufferToBase64(buffer) {
        const binary = String.fromCharCode.apply(null, new Uint8Array(buffer));
        return btoa(binary);
    }

    /**
     * Convert Base64 string to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const buffer = new ArrayBuffer(binary.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binary.length; i++) {
            view[i] = binary.charCodeAt(i);
        }
        return buffer;
    }

    /**
     * Generate unique message ID
     */
    generateMessageId() {
        return 'msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
}

window.E2ECrypto = E2ECrypto;
