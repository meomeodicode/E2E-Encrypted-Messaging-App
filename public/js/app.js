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
        
        this.init();
    }

    async init() {
        console.log('🚀 App initialization started');
        
        // Add timeout fallback to prevent infinite loading
        setTimeout(() => {
            const loadingOverlay = document.getElementById('loadingOverlay');
            if (loadingOverlay && window.getComputedStyle(loadingOverlay).display !== 'none') {
                console.warn('⚠️ Loading timeout - forcing auth modal');
                console.log('🔧 Manually hiding loading overlay and showing auth modal');
                
                // Force hide loading overlay
                loadingOverlay.style.display = 'none';
                
                // Force show auth modal
                this.showAuthModal();
            }
        }, 5000); // Reduced to 5 second timeout for faster debugging
        
        try {
            await this.setupEventListeners();
            console.log('✅ Event listeners setup complete');
            
            await this.checkAuthToken();
            console.log('✅ Auth check complete');
        } catch (error) {
            console.error('❌ App initialization failed:', error);
            this.showAuthModal();
        }
    }

    async checkAuthToken() {
        console.log('🔍 Checking authentication token...');
        
        const token = localStorage.getItem('token');
        const user = localStorage.getItem('user');
        
        console.log('Token exists:', !!token);
        console.log('User exists:', !!user);

        if (token && user) {
            console.log('✅ Found existing auth, initializing app...');
            try {
                this.currentUser = JSON.parse(user);
                await this.initializeApp();
            } catch (error) {
                console.error('❌ App initialization failed:', error);
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                this.showAuthModal();
            }
        } else {
            console.log('❌ No existing auth, showing login');
            this.showAuthModal();
        }
    }

    showAuthModal() {
        console.log('🔄 Showing auth modal...');
        document.getElementById('loadingOverlay').style.display = 'none';
        document.getElementById('authModal').style.display = 'flex';
        document.getElementById('app').style.display = 'none';
        
        console.log('✅ Auth modal displayed');
    }

    hideAuthModal() {
        console.log('🔄 Hiding auth modal...');
        
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

        try {
            let body = { username, password };
            let publicKeyBase64 = '';

            if (!isLogin) {
                console.log('📝 Registration: generating encryption keys...');
                document.getElementById('loadingOverlay').style.display = 'flex';
                
                try {
                    await this.crypto.generateKeyPair();
                    publicKeyBase64 = await this.crypto.exportPublicKey();
                    
                    body.publicKey = publicKeyBase64;
                } catch (error) {
                    console.error('Key generation failed:', error);
                    document.getElementById('loadingOverlay').style.display = 'none';
                    errorDiv.textContent = 'Failed to generate encryption keys. Please try again.';
                    return;
                }
                
                document.getElementById('loadingOverlay').style.display = 'none';
            }

            console.log('🌐 Sending authentication request...');
            const response = await fetch(`/api/${isLogin ? 'login' : 'register'}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body)
            });

            const data = await response.json();

            if (response.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                this.currentUser = data.user;

                if (isLogin) {
                    document.getElementById('loadingOverlay').style.display = 'flex';
                    await this.crypto.generateKeyPair();
                    document.getElementById('loadingOverlay').style.display = 'none';
                }

                await this.initializeApp();
            } else {
                errorDiv.textContent = data.error || 'Authentication failed';
            }
        } catch (error) {
            console.error('Auth error:', error);
            errorDiv.textContent = 'Connection error. Please try again.';
            document.getElementById('loadingOverlay').style.display = 'none';
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

        const token = localStorage.getItem('token');
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
            const token = localStorage.getItem('token');
            const response = await fetch('/api/users', {
                headers: {
                    'x-auth-token': token
                }
            });

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
            const token = localStorage.getItem('token');
            const response = await fetch(`/api/messages/${contactId}`, {
                headers: {
                    'x-auth-token': token
                }
            });

            if (response.ok) {
                const messages = await response.json();
                
                const decryptedMessages = [];
                for (const message of messages) {
                    try {
                        const decryptedContent = await this.crypto.decryptMessage(message.encrypted_content);
                        decryptedMessages.push({
                            ...message,
                            content: decryptedContent,
                            isSent: message.sender_id === this.currentUser.id
                        });
                    } catch (error) {
                        console.error('Failed to decrypt message:', error);
                        decryptedMessages.push({
                            ...message,
                            content: '[Failed to decrypt message]',
                            isSent: message.sender_id === this.currentUser.id,
                            isError: true
                        });
                    }
                }

                this.messages.set(contactId, decryptedMessages);
                this.renderMessages();
            }
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
            const token = localStorage.getItem('token');
            const response = await fetch(`/api/users/${this.selectedContact.username}/publickey`, {
                headers: {
                    'x-auth-token': token
                }
            });

            if (!response.ok) {
                throw new Error('Failed to get recipient public key');
            }

            const { publicKey } = await response.json();

            const encryptedContent = await this.crypto.encryptMessage(content, publicKey);
            const messageId = this.crypto.generateMessageId();

            this.socket.emit('private_message', {
                receiverId: this.selectedContact.id,
                encryptedContent: encryptedContent,
                messageId: messageId
            });

            const messages = this.messages.get(this.selectedContact.id) || [];
            messages.push({
                id: messageId,
                sender_id: this.currentUser.id,
                receiver_id: this.selectedContact.id,
                content: content,
                timestamp: new Date().toISOString(),
                isSent: true
            });
            this.messages.set(this.selectedContact.id, messages);

            messageInput.value = '';
            this.renderMessages();

        } catch (error) {
            console.error('Error sending message:', error);
            alert('Failed to send message. Please try again.');
        }
    }

    async handleNewMessage(data) {
        try {
            const decryptedContent = await this.crypto.decryptMessage(data.encryptedContent);

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

    logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        
        if (this.socket) {
            this.socket.disconnect();
        }

        this.currentUser = null;
        this.selectedContact = null;
        this.contacts = [];
        this.onlineUsers.clear();
        this.typingUsers.clear();
        this.messages.clear();

        document.getElementById('messageInput').disabled = true;
        document.getElementById('sendBtn').disabled = true;
        document.getElementById('noChatSelected').style.display = 'flex';
        document.getElementById('chatContainer').style.display = 'none';

        this.showAuthModal();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new MessagingApp();
});
