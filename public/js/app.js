class MessagingApp {
    constructor() {
        this.socket = null;
        this.currentUser = null;
        this.selectedContact = null;
        this.crypto = new E2ECrypto();
        this.contacts = [];
        this.onlineUsers = new Set();
        this.typingUsers = new Set();
        this.messages = new Map();
        window.addEventListener('auth-failure', () => {
            console.log('Authentication failure detected. Logging out.');
            this.logout();
        });
        this.init();
    }

    async init() {
        try {
            await this.setupEventListeners();
            await this.checkAuthToken();
        } catch (error) {
            console.error('App initialization failed:', error);
            this.showAuthModal();
        }
    }

    async checkAuthToken() {
        const accessToken = localStorage.getItem('accessToken');
        const refreshToken = localStorage.getItem('refreshToken');
        const user = localStorage.getItem('user');

        if (refreshToken && user) {
            try {
                this.currentUser = JSON.parse(user);
                if (!accessToken) {
                    const newAccessToken = await window.api.refreshToken();
                    if (!newAccessToken) {
                        this.clearAuthData();
                        this.showAuthModal();
                        return;
                    }
                }
                
                await this.crypto.initializeForUser(this.currentUser.id);
                try {
                    const { privateKey: signPriv } = await getOrCreateSigningKeyPair(this.currentUser.id);
                    this.signPrivateKey = signPriv;
                    console.log('Signing key loaded into application state.');
                } catch (err) {
                    console.error('Failed to load signing key on session resume:', err);
                    alert('Error loading your signing key. Please log in again.');
                    this.logout();
                    return;
                }
                await this.initializeApp();
            } catch (error) {
                console.error('Authentication initialization failed:', error);
                this.clearAuthData();
                this.showAuthModal();
            }
        } else {
            this.showAuthModal();
        }
    }

    clearAuthData() {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        this.crypto = new E2ECrypto();
    }

    emergencyCleanup() {
        const keys = Object.keys(localStorage);
        keys.forEach(key => {
            if (key.startsWith('privateKey_') || key.startsWith('publicKey_')) {
                localStorage.removeItem(key);
            }
        });
        
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        
        this.crypto = new E2ECrypto();
        window.location.reload();
    }

    showAuthModal() {
        document.getElementById('loadingOverlay').style.display = 'none';
        document.getElementById('authModal').style.display = 'flex';
        document.getElementById('app').style.display = 'none';
    }

    hideAuthModal() {
        document.getElementById('loadingOverlay').style.display = 'none';
        document.getElementById('authModal').style.display = 'none';
        document.getElementById('app').style.display = 'block';
    }

    async setupEventListeners() {
        const authForm = document.getElementById('authForm');
        const toggleAuth = document.getElementById('toggleAuth');
        const logoutBtn = document.getElementById('logoutBtn');

        authForm.addEventListener('submit', (e) => this.handleAuth(e));
        toggleAuth.addEventListener('click', (e) => this.toggleAuthMode(e));
        logoutBtn.addEventListener('click', () => this.logout());

        const messageInput = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');

        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        messageInput.addEventListener('input', () => this.handleTyping());
        sendBtn.addEventListener('click', () => this.sendMessage());
    }

    toggleAuthMode(e) {
        e.preventDefault();
        const authTitle = document.getElementById('authTitle');
        const authSubmit = document.getElementById('authSubmit');
        const authToggle = document.getElementById('authToggle');
        const isLogin = authTitle.textContent === 'Login';

        if (isLogin) {
            authTitle.textContent = 'Register';
            authSubmit.textContent = 'Register';
            authToggle.innerHTML = 'Already have an account? <a href="#" id="toggleAuth">Login</a>';
        } else {
            authTitle.textContent = 'Login';
            authSubmit.textContent = 'Login';
            authToggle.innerHTML = 'Don\'t have an account? <a href="#" id="toggleAuth">Register</a>';
        }

        document.getElementById('toggleAuth').addEventListener('click', (e) => this.toggleAuthMode(e));
        document.getElementById('authError').textContent = '';
    }

    async handleAuth(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const isLogin = document.getElementById('authTitle').textContent === 'Login';
        const errorDiv = document.getElementById('authError');
    
        errorDiv.textContent = '';
    
        if (!username || !password) {
            errorDiv.textContent = 'Please enter username and password';
            return;
        }
    
        document.getElementById('loadingOverlay').style.display = 'flex';
        const loadingText = document.querySelector('#loadingOverlay p');
    
        try {
            let response;
            let requestBody = { username, password };
            let cryptoForRegistration = null; 
    
            if (isLogin) {
                if (loadingText) loadingText.textContent = 'Logging in...';
                response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(requestBody)
                });
    
            } else {
                if (loadingText) loadingText.textContent = 'Generating encryption keys...';
                
                cryptoForRegistration = new E2ECrypto();
                await cryptoForRegistration.generateKeyPair(); 
                const publicKey = await cryptoForRegistration.exportPublicKey();
    
                requestBody.publicKey = publicKey;
    
                if (loadingText) loadingText.textContent = 'Creating account...';
                response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(requestBody)
                });
            }
    
            const data = await response.json();
    
            if (response.ok) {
                localStorage.setItem('accessToken', data.accessToken);
                localStorage.setItem('refreshToken', data.refreshToken);
                localStorage.setItem('user', JSON.stringify(data.user));
                this.currentUser = data.user;
                
                //Digital Signature: create & upload signing public key ===
                try {
                    const { privateKey: signPriv, publicKeySpkiB64: signPubB64 } =
                        await getOrCreateSigningKeyPair(this.currentUser.id);

                    this.signPrivateKey = signPriv;

                    const res = await fetch('/api/user/signingkey', {
                        method: 'PUT',
                        headers: {
                        'Content-Type': 'application/json',
                        'x-auth-token': data.accessToken   
                        },
                        body: JSON.stringify({ signingPublicKey: signPubB64 })
                    });

                    if (!res.ok) {
                        console.warn('Failed to upload signing key:', await res.text());
                    } else {
                        console.log('Signing key uploaded');
                    }
                } catch (err) {
                    console.error('Error generating/uploading signing key:', err);
                }

                if (!isLogin && cryptoForRegistration) {
                    if (loadingText) loadingText.textContent = 'Securing your keys...';
                    await cryptoForRegistration.saveKeyPair(data.user.id);
                }
    
                await this.crypto.initializeForUser(data.user.id);
                await this.initializeApp();
    
            } else {
                errorDiv.textContent = data.error || 'Authentication failed';
            }
        } catch (error) {
            console.error('Authentication error:', error);
            errorDiv.textContent = 'Connection error. Please try again.';
        } finally {
            document.getElementById('loadingOverlay').style.display = 'none';
        }
    }

    async updateUserPublicKey(publicKey) {
        try {
            const response = await window.api.request('/api/user/publickey', {
                method: 'PUT',
                body: JSON.stringify({ publicKey })
            });
    
            if (response.ok) {
                console.log('✅ Public key updated on server');
            } else {
                console.error('Failed to update public key on server');
            }
        } catch (error) {
            console.error('Error updating public key:', error);
        }
    }

    async initializeApp() {
        this.hideAuthModal();
        document.getElementById('currentUser').textContent = this.currentUser.username;
        this.initializeSocket();
        await this.loadContacts();
    }
    
    initializeSocket() {
        this.socket = io();

        const token = localStorage.getItem('accessToken');
        this.socket.emit('authenticate', token);

        this.socket.on('authenticated', () => {
            console.log('Socket authenticated');
        });

        this.socket.on('authentication_error', (data) => {
            console.error('Socket authentication error:', data.error);
            this.logout();
        });

        this.socket.on('new_message', (data) => {
            this.handleNewMessage(data);
        });

        this.socket.on('user_online', (data) => {
            this.onlineUsers.add(data.userId);
            this.updateContactStatus(data.userId, true);
        });

        this.socket.on('user_offline', (data) => {
            this.onlineUsers.delete(data.userId);
            this.updateContactStatus(data.userId, false);
        });
        
        this.socket.on('initial_online_users', (onlineUserIds) => {
            console.log('Received initial list of online users:', onlineUserIds);
            this.onlineUsers = new Set(onlineUserIds);
            
            if (this.contacts.length > 0) {
                this.renderContacts();
            }
        });

        this.socket.on('user_typing', (data) => {
            this.typingUsers.add(data.userId);
            this.updateTypingIndicator();
        });

        this.socket.on('user_stopped_typing', (data) => {
            this.typingUsers.delete(data.userId);
            this.updateTypingIndicator();
        });

        this.socket.on('message_sent', (data) => {
            console.log('Message sent confirmation:', data.messageId);
        });

        this.socket.on('message_error', (data) => {
            console.error('Message error:', data.error);
        });
    }

    async loadContacts() {
        try {
            const response = await window.api.request('/api/users');
    
            if (response.ok) {
                this.contacts = await response.json();
                this.renderContacts();
            } else {
                console.error('Failed to load contacts');
            }
        } catch (error) {
            console.error('Error loading contacts:', error);
        }
    }

    renderContacts() {
        const contactsList = document.getElementById('contactsList');
        contactsList.innerHTML = '';

        this.contacts.forEach(contact => {
            const contactElement = document.createElement('div');
            contactElement.className = 'contact-item';
            contactElement.dataset.userId = contact.id;

            const isOnline = this.onlineUsers.has(contact.id);
            
            contactElement.innerHTML = `
                <div class="contact-info">
                    <div class="contact-name">${contact.username}</div>
                    <div class="contact-status">${isOnline ? 'Online' : 'Offline'}</div>
                </div>
                <div class="${isOnline ? 'online-indicator' : 'offline-indicator'}"></div>
            `;

            contactElement.addEventListener('click', () => this.selectContact(contact));
            contactsList.appendChild(contactElement);
        });
    }

    updateContactStatus(userId, isOnline) {
        const contactElement = document.querySelector(`[data-user-id="${userId}"]`);
        if (contactElement) {
            const statusElement = contactElement.querySelector('.contact-status');
            const indicatorElement = contactElement.querySelector('.online-indicator, .offline-indicator');
            
            if (statusElement) {
                statusElement.textContent = isOnline ? 'Online' : 'Offline';
            }
            
            if (indicatorElement) {
                indicatorElement.className = isOnline ? 'online-indicator' : 'offline-indicator';
            }
        }

        if (this.selectedContact && this.selectedContact.id === userId) {
            const onlineStatus = document.getElementById('onlineStatus');
            onlineStatus.textContent = isOnline ? 'Online' : 'Offline';
            onlineStatus.className = `online-status ${isOnline ? 'online' : ''}`;
        }
    }

    async selectContact(contact) {
        document.querySelectorAll('.contact-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-user-id="${contact.id}"]`).classList.add('active');

        this.selectedContact = contact;

        document.getElementById('noChatSelected').style.display = 'none';
        document.getElementById('chatContainer').style.display = 'flex';

        document.getElementById('chatPartner').textContent = contact.username;
        const isOnline = this.onlineUsers.has(contact.id);
        const onlineStatus = document.getElementById('onlineStatus');
        onlineStatus.textContent = isOnline ? 'Online' : 'Offline';
        onlineStatus.className = `online-status ${isOnline ? 'online' : ''}`;

        document.getElementById('messageInput').disabled = false;
        document.getElementById('sendBtn').disabled = false;

        await this.loadMessageHistory(contact.id);
    }

    async loadMessageHistory(contactId) {
        try {
            const token = localStorage.getItem('accessToken'); 
            const response = await window.api.request(`/api/messages/${contactId}`);
    
            if (!response.ok) {
                throw new Error('Failed to load messages');
            }
    
            const messages = await response.json(); 
            const decryptedMessages = [];
            const serverMessageIds = new Set(messages.map(msg => msg.id));
    
            const existingMessages = this.messages.get(contactId) || [];
        
            const uniqueLocalMessages = existingMessages.filter(msg => {
                return msg.isLocal && !serverMessageIds.has(msg.id);
            });
            for (const message of messages) {
                const isSentByMe = message.sender_id === this.currentUser.id;
                const isForMe = message.receiver_id === this.currentUser.id; 
                
                if (isSentByMe) {
                    decryptedMessages.push({
                        ...message,
                        content: '[Encrypted message you sent]',
                        isSent: true,
                        isEncrypted: true
                    });
                } else if (isForMe) {
                    try {
                        const decryptedContent = await this.crypto.decryptMessage(message.encrypted_content);
                        decryptedMessages.push({
                            ...message,
                            content: decryptedContent,
                            isSent: false
                        });
                    } catch (error) {
                        decryptedMessages.push({
                            ...message,
                            content: '[Failed to decrypt message]',
                            isSent: false,
                            isError: true
                        });
                    }
                } else {
                    decryptedMessages.push({
                        ...message,
                        content: '[Message not for you]',
                        isSent: false,
                        isError: true
                    });
                }
            }
    
            const allMessages = [...decryptedMessages, ...uniqueLocalMessages];
            allMessages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    
            this.messages.set(contactId, allMessages);
            this.renderMessages();
        } catch (error) {
            console.error('Error loading message history:', error);
        }
    }

    renderMessages() {
        const messagesContainer = document.getElementById('messagesContainer');
        messagesContainer.innerHTML = '';

        const messages = this.messages.get(this.selectedContact.id) || [];

        messages.forEach(message => {
            const messageElement = document.createElement('div');
            messageElement.className = `message ${message.isSent ? 'sent' : 'received'}`;

            const bubble = document.createElement('div');
            bubble.className = 'message-bubble';

            if (!message.isSent) {
                const sender = document.createElement('div');
                sender.className = 'message-sender';
                sender.textContent = message.sender_username || this.selectedContact.username;
                bubble.appendChild(sender);
            }

            const content = document.createElement('div');
            content.className = 'message-content';
            content.textContent = message.content;
            if (message.isError) {
                content.style.color = '#e53e3e';
                content.style.fontStyle = 'italic';
            }
            bubble.appendChild(content);

            const time = document.createElement('div');
            time.className = 'message-time';
            time.textContent = new Date(message.timestamp).toLocaleTimeString();
            bubble.appendChild(time);

            messageElement.appendChild(bubble);
            messagesContainer.appendChild(messageElement);
        });

        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }


    async sendMessage() {
        const messageInput = document.getElementById('messageInput');
        const content = messageInput.value.trim();
    
        if (!content || !this.selectedContact) {
            return;
        }
    
        try {
            const response = await window.api.request(`/api/users/${this.selectedContact.username}/publickey`);
    
            if (!response.ok) {
                throw new Error('Failed to get recipient public key');
            }
    
            const { publicKey } = await response.json();
            if (!publicKey) {
                throw new Error('Recipient does not have a public key available.');
            }
            
            const timestamp = new Date().toISOString();
            const payloadToSign = JSON.stringify({
                senderId: this.currentUser.id,
                receiverId: this.selectedContact.id,
                plaintext: content,
                timestamp
            });

            const signature = await signMessage(this.signPrivateKey, payloadToSign);
            
            const encryptedContent = await this.crypto.encryptMessage(content, publicKey);
            const messageId = this.crypto.generateMessageId();
            
            this.socket.emit('private_message', {
                receiverId: this.selectedContact.id,
                encryptedContent: encryptedContent,
                messageId: messageId,
                signature: signature,
                signingTimestamp: timestamp
            });
    
            const messages = this.messages.get(this.selectedContact.id) || [];
            messages.push({
                id: messageId,
                sender_id: this.currentUser.id,
                receiver_id: this.selectedContact.id,
                content: content, 
                timestamp: timestamp,
                isSent: true,
                isLocal: true 
            });
            this.messages.set(this.selectedContact.id, messages);
    
            messageInput.value = '';
            this.renderMessages();
    
        } catch (error) {
            console.error('Error sending message:', error);
            alert(`Failed to send message: ${error.message}. Please try again.`);
        }
    }

    async handleNewMessage(data) {
        try {
            console.log("Step 1: handleNewMessage START", data);
            
            console.log("Step 2: check receiverId");
            if (data.receiverId !== this.currentUser.id) {
                console.warn('⚠️ Message not intended for this user');
            }
            
            console.log("Step 3: start decrypt");
            let decryptedContent;
            try {
                decryptedContent = await this.crypto.decryptMessage(data.encryptedContent); 
            } catch (error) {
                console.error('Failed to decrypt incoming message:', error);
                return;
            }
            console.log("Step 3: decryptedContent =", decryptedContent);

            console.log("Step 4: build payloadToVerify");
            const payloadToVerify = JSON.stringify({
                senderId: data.senderId,
                receiverId: data.receiverId,
                plaintext: decryptedContent,
                timestamp: data.signingTimestamp,
            });

            console.log("Step 5: fetch or get signingPublicKey");
            if (!this.signingKeys) this.signingKeys = new Map();
            let signingPublicKey = this.signingKeys.get(data.senderId);

            if (!signingPublicKey) {
                console.log("Step 5a: fetch from API");
                const response = await window.api.request(
                    `/api/user/${encodeURIComponent(data.senderUsername)}/signingkey`
                );
                if (response.ok) {
                    const result = await response.json();
                    signingPublicKey = await importSpkiRsaPss(result.signingPublicKey);
                    this.signingKeys.set(data.senderId, signingPublicKey);
                } else {
                    console.warn('Could not fetch signing key for user:', data.senderUsername);
                    return; 
                }
            }

            console.log("Step 6: verify signature");
            const isValid = await verifyMessage(signingPublicKey, payloadToVerify, data.signature);
            console.log("Step 6: isValid =", isValid);
            if (!isValid) {
                console.warn("Message signature invalid!");
                return;
            }

            console.log("Step 7: store and render");
            const messages = this.messages.get(data.senderId) || [];
            messages.push({
                id: data.id,
                sender_id: data.senderId,
                sender_username: data.senderUsername,
                receiver_id: this.currentUser.id,
                content: decryptedContent,
                timestamp: data.timestamp,
                isSent: false
            });
            this.messages.set(data.senderId, messages);

            if (this.selectedContact && this.selectedContact.id === data.senderId) {
                this.renderMessages();
            }

        } catch (error) {
            console.error('Failed to handle new message:', error);
        }
    }

    handleTyping() {
        if (this.selectedContact && this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }

        if (this.selectedContact) {
            this.socket.emit('typing_start', { receiverId: this.selectedContact.id });

            this.typingTimeout = setTimeout(() => {
                this.socket.emit('typing_stop', { receiverId: this.selectedContact.id });
            }, 2000);
        }
    }

    updateTypingIndicator() {
        const typingIndicator = document.getElementById('typingIndicator');
        
        if (this.selectedContact && this.typingUsers.has(this.selectedContact.id)) {
            typingIndicator.textContent = `${this.selectedContact.username} is typing...`;
        } else {
            typingIndicator.textContent = '';
        }
    }

    async logout() {
        try {
            await window.api.request('/api/logout', { method: 'POST' });
        } catch (error) {
            console.error("Logout API call failed, proceeding with client-side cleanup.", error);
        }
    
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }

        this.currentUser = null;
        this.selectedContact = null;
        this.contacts = [];
        this.onlineUsers.clear();
        this.typingUsers.clear();
        this.messages.clear();

        // Clear any typing timeout
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
            this.typingTimeout = null;
        }

        // Reset UI
        document.getElementById('messageInput').disabled = true;
        document.getElementById('sendBtn').disabled = true;
        document.getElementById('noChatSelected').style.display = 'flex';
        document.getElementById('chatContainer').style.display = 'none';
        
        // Clear form inputs
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
        document.getElementById('authError').textContent = '';

        this.showAuthModal();
    }

    
}


document.addEventListener('DOMContentLoaded', () => {
    new MessagingApp();
});


