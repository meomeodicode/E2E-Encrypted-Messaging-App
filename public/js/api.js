class ApiClient {
    constructor() {
        this.baseUrl = '';
    }

    async request(endpoint, options = {}) {
        let accessToken = localStorage.getItem('accessToken');

        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        if (accessToken) {
            headers['x-auth-token'] = accessToken;
        }

        const config = {
            ...options,
            headers,
        };

        let response = await fetch(this.baseUrl + endpoint, config);

        if (response.status === 401) {
            console.log('Access token expired, attempting to refresh...');
            const newAccessToken = await this.refreshToken();

            if (newAccessToken) {
                // Retry the original request with the new token
                config.headers['x-auth-token'] = newAccessToken;
                response = await fetch(this.baseUrl + endpoint, config);
            } else {
                // If refresh fails, logout the user
                // This could be handled by emitting a custom event
                window.dispatchEvent(new CustomEvent('auth-failure'));
                return Promise.reject('Authentication failed');
            }
        }

        return response;
    }

    async refreshToken() {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) {
            return null;
        }

        try {
            const response = await fetch('/api/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: refreshToken }),
            });

            if (response.ok) {
                const { accessToken } = await response.json();
                localStorage.setItem('accessToken', accessToken);
                return accessToken;
            } else {
                localStorage.removeItem('accessToken');
                localStorage.removeItem('refreshToken');
                return null;
            }
        } catch (error) {
            console.error('Refresh token request failed:', error);
            return null;
        }
    }
}

// Export a singleton instance
window.api = new ApiClient();