package embed

import (
	"context"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/client/internal/auth"
)

// SSHAuthInfo carries the OIDC device-flow details a UI needs to open the
// browser and show the user code (#875). The NetBird SSH server authenticates
// the resulting JWT as the SSH password (see client/ssh.AddJWTAuth).
type SSHAuthInfo struct {
	VerificationURI         string
	VerificationURIComplete string
	UserCode                string
	DeviceCode              string
	ExpiresIn               int64
}

// sshAuthState holds the in-flight device flow between RequestSSHAuth and
// WaitSSHAuth.
type sshAuthState struct {
	flow      auth.OAuthFlow
	info      auth.AuthFlowInfo
	expiresAt time.Time
}

// RequestSSHAuth starts the NetBird SSH JWT OIDC device flow and returns the
// verification URI and user code the UI should present. Android has no
// localhost redirect for the PKCE flow, so the device code flow is forced.
// Call WaitSSHAuth with the returned DeviceCode after the user authenticates.
func (c *Client) RequestSSHAuth(ctx context.Context, hint string) (*SSHAuthInfo, error) {
	c.mu.Lock()
	config := c.config
	c.mu.Unlock()
	if config == nil {
		return nil, fmt.Errorf("client is not configured")
	}

	flow, err := auth.NewOAuthFlow(ctx, config, false, true, hint)
	if err != nil {
		return nil, fmt.Errorf("create oauth flow: %w", err)
	}
	info, err := flow.RequestAuthInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("request auth info: %w", err)
	}

	c.sshMu.Lock()
	c.sshAuth = sshAuthState{
		flow:      flow,
		info:      info,
		expiresAt: time.Now().Add(time.Duration(info.ExpiresIn) * time.Second),
	}
	c.sshMu.Unlock()

	return &SSHAuthInfo{
		VerificationURI:         info.VerificationURI,
		VerificationURIComplete: info.VerificationURIComplete,
		UserCode:                info.UserCode,
		DeviceCode:              info.DeviceCode,
		ExpiresIn:               int64(info.ExpiresIn),
	}, nil
}

// WaitSSHAuth blocks until the user completes the browser authentication for
// the device flow started by RequestSSHAuth, then returns the JWT to use as
// the SSH password. The token is cached for CachedSSHJWT.
func (c *Client) WaitSSHAuth(ctx context.Context, deviceCode string) (string, error) {
	c.sshMu.Lock()
	st := c.sshAuth
	c.sshMu.Unlock()
	if st.flow == nil || st.info.DeviceCode != deviceCode {
		return "", fmt.Errorf("no active auth flow for device code")
	}

	tokenInfo, err := st.flow.WaitToken(ctx, st.info)
	if err != nil {
		return "", fmt.Errorf("wait for token: %w", err)
	}
	token := tokenInfo.GetTokenToUse()

	c.sshMu.Lock()
	c.sshJWT = token
	c.sshJWTExpiry = time.Now().Add(time.Duration(tokenInfo.ExpiresIn) * time.Second)
	c.sshAuth = sshAuthState{}
	c.sshMu.Unlock()

	return token, nil
}

// CachedSSHJWT returns the last JWT obtained via WaitSSHAuth if it has not
// expired, or an empty string. Lets a caller reuse a token across SSH
// connections without repeating the browser flow.
func (c *Client) CachedSSHJWT() string {
	c.sshMu.Lock()
	defer c.sshMu.Unlock()
	if c.sshJWT == "" || time.Now().After(c.sshJWTExpiry) {
		return ""
	}
	return c.sshJWT
}