class E2ECrypto {
    constructor() {
        this.keyPair = null;
        this.publicKeyCache = new Map(); 
    }

    async generateKeyPair() {
        console.log('🔑 Starting RSA key generation...');
        console.log('🔐 Crypto.subtle available:', !!window.crypto?.subtle);
        
        if (!window.crypto?.subtle) {
            throw new Error('Web Crypto API not available. Requires HTTPS or localhost.');
        }
        
        try {
            console.log('⏳ Generating 2048-bit RSA key pair...');
            
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

            console.log('✅ Key pair generated successfully!');
            return this.keyPair;
        } catch (error) {
            console.error('❌ Key generation failed:', error);
            throw error;
        }
    }

    async exportPublicKey() {
        if (!this.keyPair) {
            throw new Error('Key pair not generated');
        }

        try {
            const exported = await window.crypto.subtle.exportKey(
                "spki",
                this.keyPair.publicKey
            );

            return this.arrayBufferToBase64(exported);
        } catch (error) {
            console.error('Error exporting public key:', error);
            throw error;
        }
    }

    async importPublicKey(publicKeyBase64) {
        try {
            const keyBuffer = this.base64ToArrayBuffer(publicKeyBase64);
            const publicKey = await window.crypto.subtle.importKey(
                "spki",
                keyBuffer,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                false,
                ["encrypt"]
            );

            return publicKey;
        } catch (error) {
            console.error('Error importing public key:', error);
            throw error;
        }
    }

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
                encryptedMessage: this.arrayBufferToBase64(encryptedMessage),
                iv: this.arrayBufferToBase64(iv)
            };

            return JSON.stringify(result);
        } catch (error) {
            console.error('Error encrypting message:', error);
            throw error;
        }
    }

    async decryptMessage(encryptedData) {
        try {
            if (!this.keyPair) {
                throw new Error('Key pair not available');
            }

            const data = JSON.parse(encryptedData);
            
            const encryptedAESKeyBuffer = this.base64ToArrayBuffer(data.encryptedAESKey);
            const decryptedAESKeyBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP"
                },
                this.keyPair.privateKey,
                encryptedAESKeyBuffer
            );

            const aesKey = await window.crypto.subtle.importKey(
                "raw",
                decryptedAESKeyBuffer,
                {
                    name: "AES-GCM",
                    length: 256
                },
                false,
                ["decrypt"]
            );

            const encryptedMessageBuffer = this.base64ToArrayBuffer(data.encryptedMessage);
            const ivBuffer = this.base64ToArrayBuffer(data.iv);

            const decryptedMessageBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: ivBuffer
                },
                aesKey,
                encryptedMessageBuffer
            );

            const decoder = new TextDecoder();
            return decoder.decode(decryptedMessageBuffer);
        } catch (error) {
            console.error('Error decrypting message:', error);
            throw error;
        }
    }

    arrayBufferToBase64(buffer) {
        const binary = String.fromCharCode.apply(null, new Uint8Array(buffer));
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const buffer = new ArrayBuffer(binary.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binary.length; i++) {
            view[i] = binary.charCodeAt(i);
        }
        return buffer;
    }

    generateMessageId() {
        return 'msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
}

window.E2ECrypto = E2ECrypto;
