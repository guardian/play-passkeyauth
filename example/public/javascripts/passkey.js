// WebAuthn client-side code for the passkey example application

/**
 * Display a message to the user
 */
function showMessage(message, isError = false) {
    const messagesDiv = document.getElementById('messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isError ? 'error' : 'success'}`;
    messageDiv.textContent = message;
    messagesDiv.appendChild(messageDiv);

    // Auto-remove after 5 seconds
    setTimeout(() => messageDiv.remove(), 5000);
}

/**
 * Convert ArrayBuffer to Base64URL string
 */
function bufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    const binary = String.fromCharCode(...bytes);
    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Convert Base64URL string to ArrayBuffer
 */
function base64URLToBuffer(base64url) {
    const base64 = base64url
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Transform server's PublicKeyCredentialCreationOptions to browser format
 */
function transformCreationOptions(options) {
    return {
        ...options,
        challenge: base64URLToBuffer(options.challenge),
        user: {
            ...options.user,
            id: base64URLToBuffer(options.user.id)
        },
        excludeCredentials: options.excludeCredentials?.map(cred => ({
            ...cred,
            id: base64URLToBuffer(cred.id)
        }))
    };
}

/**
 * Transform server's PublicKeyCredentialRequestOptions to browser format
 */
function transformRequestOptions(options) {
    return {
        ...options,
        challenge: base64URLToBuffer(options.challenge),
        allowCredentials: options.allowCredentials?.map(cred => ({
            ...cred,
            id: base64URLToBuffer(cred.id)
        }))
    };
}

/**
 * Transform browser's credential to server format
 */
function transformCredential(credential) {
    return {
        id: credential.id,
        rawId: bufferToBase64URL(credential.rawId),
        type: credential.type,
        response: {
            attestationObject: bufferToBase64URL(credential.response.attestationObject),
            clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON)
        }
    };
}

/**
 * Transform browser's assertion to server format
 */
function transformAssertion(assertion) {
    return {
        id: assertion.id,
        rawId: bufferToBase64URL(assertion.rawId),
        type: assertion.type,
        response: {
            authenticatorData: bufferToBase64URL(assertion.response.authenticatorData),
            clientDataJSON: bufferToBase64URL(assertion.response.clientDataJSON),
            signature: bufferToBase64URL(assertion.response.signature),
            userHandle: assertion.response.userHandle ? bufferToBase64URL(assertion.response.userHandle) : null
        }
    };
}

/**
 * Register a new passkey
 */
async function registerPasskey() {
    try {
        const nameInput = document.getElementById('passkeyName');
        const name = nameInput.value.trim();

        if (!name) {
            showMessage('Please enter a name for your passkey', true);
            return;
        }

        // Step 1: Get creation options from server
        const optionsResponse = await fetch('/register/options');
        if (!optionsResponse.ok) {
            throw new Error('Failed to get registration options');
        }
        const serverOptions = await optionsResponse.json();

        // Step 2: Transform options for browser API
        const options = transformCreationOptions(serverOptions);

        // Step 3: Create credential using WebAuthn
        const credential = await navigator.credentials.create({
            publicKey: options
        });

        if (!credential) {
            throw new Error('Failed to create credential');
        }

        // Step 4: Transform credential for server
        const credentialData = transformCredential(credential);

        // Step 5: Send credential to server
        const registerResponse = await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: name,
                credential: credentialData
            })
        });

        if (!registerResponse.ok) {
            const error = await registerResponse.json();
            throw new Error(error.error || 'Registration failed');
        }

        showMessage('Passkey registered successfully! ✓');
        nameInput.value = '';
        loadPasskeys();
    } catch (error) {
        console.error('Registration error:', error);
        showMessage('Registration failed: ' + error.message, true);
    }
}

/**
 * Authenticate with a passkey
 */
async function authenticate() {
    try {
        // Step 1: Get authentication options from server
        const optionsResponse = await fetch('/auth/options');
        if (!optionsResponse.ok) {
            throw new Error('Failed to get authentication options');
        }
        const serverOptions = await optionsResponse.json();

        // Step 2: Transform options for browser API
        const options = transformRequestOptions(serverOptions);

        // Step 3: Get credential using WebAuthn
        const assertion = await navigator.credentials.get({
            publicKey: options
        });

        if (!assertion) {
            throw new Error('Failed to get credential');
        }

        // Step 4: Transform assertion for server
        const assertionData = transformAssertion(assertion);

        // Step 5: Send assertion to server
        const authResponse = await fetch('/auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                assertion: assertionData
            })
        });

        if (!authResponse.ok) {
            const error = await authResponse.json();
            throw new Error(error.error || 'Authentication failed');
        }

        showMessage('Authentication successful! ✓');
        loadPasskeys();
    } catch (error) {
        console.error('Authentication error:', error);
        showMessage('Authentication failed: ' + error.message, true);
    }
}

/**
 * Load and display all passkeys
 */
async function loadPasskeys() {
    try {
        const response = await fetch('/passkeys');
        if (!response.ok) {
            throw new Error('Failed to load passkeys');
        }

        const passkeys = await response.json();
        const listDiv = document.getElementById('passkeyList');

        if (passkeys.length === 0) {
            listDiv.innerHTML = '<p>No passkeys registered yet.</p>';
            return;
        }

        listDiv.innerHTML = passkeys.map(passkey => `
            <div class="passkey-item">
                <strong>${escapeHtml(passkey.name)}</strong><br>
                <small>
                    ID: <code>${escapeHtml(passkey.id.substring(0, 20))}...</code><br>
                    Created: ${new Date(passkey.createdAt).toLocaleString()}<br>
                    ${passkey.lastUsedAt ? `Last used: ${new Date(passkey.lastUsedAt).toLocaleString()}` : 'Never used'}
                </small><br>
                <button class="danger" onclick="deletePasskey('${escapeHtml(passkey.id)}')">Delete</button>
            </div>
        `).join('');
    } catch (error) {
        console.error('Load passkeys error:', error);
        showMessage('Failed to load passkeys: ' + error.message, true);
    }
}

/**
 * Delete a passkey
 */
async function deletePasskey(id) {
    if (!confirm('Are you sure you want to delete this passkey?')) {
        return;
    }

    try {
        const response = await fetch(`/passkeys/${encodeURIComponent(id)}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Delete failed');
        }

        showMessage('Passkey deleted successfully');
        loadPasskeys();
    } catch (error) {
        console.error('Delete error:', error);
        showMessage('Failed to delete passkey: ' + error.message, true);
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
