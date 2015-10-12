package oidccli

import (
	"fmt"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
	"net"
	"net/http"
	"net/url"
	"time"
)

func oidcCallback(c *oidc.Client, listenAddr string) (string, chan jose.JWT, error) {
	tokenChan := make(chan jose.JWT)
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", nil, err
	}
	oac, err := c.OAuthClient()
	if err != nil {
		return "", nil, err
	}
	f := func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			return
		}
		token, err := c.ExchangeAuthCode(code)
		if err != nil {
			fmt.Fprintf(w, "error: %s", err)
			return
		}
		tokenChan <- token
		close(tokenChan)
		fmt.Fprintf(w, "Success! You can now close this window and go back to the CLI")
		l.Close()
	}
	go http.Serve(l, http.HandlerFunc(f))
	return oac.AuthCodeURL("", "", ""), tokenChan, err
}

func oauth2Callback(c *oidc.Client, listenAddr string) (string, chan *oauth2.TokenResponse, error) {
	tokenChan := make(chan *oauth2.TokenResponse)
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", nil, err
	}
	oac, err := c.OAuthClient()
	if err != nil {
		return "", nil, err
	}
	f := func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			return
		}
		token, err := oac.RequestToken(oauth2.GrantTypeAuthCode, code)
		if err != nil {
			fmt.Fprintf(w, "error: %s", err)
			return
		}
		tokenChan <- &token
		fmt.Fprintf(w, "Success! You can now close this window and go back to the CLI")
		l.Close()
	}
	go http.Serve(l, http.HandlerFunc(f))
	return oac.AuthCodeURL("", "", ""), tokenChan, err
}
func IdentityOnce(clientID, clientSecret, discoveryURL, redirectURL string) (string, chan jose.JWT, error) {
	oic, err := GetOIDCClient(clientID, clientSecret, discoveryURL, redirectURL)
	if err != nil {
		return "", nil, err
	}
	u, err := url.Parse(redirectURL)
	if err != nil {
		return "", nil, err
	}
	return oidcCallback(oic, u.Host)
}

// Grabs a refresh token and then continues to use it to refresh identities,
// returning the resulting JWT over the chan. Returns the AuthCode URL and chan of JWTs
// that will fire when an identity is refreshed.
func RefreshingIdentity(clientID, clientSecret, discoveryURL, redirectURL string) (string, chan jose.JWT, error) {
	oic, err := GetOIDCClient(clientID, clientSecret, discoveryURL, redirectURL)
	if err != nil {
		return "", nil, err
	}
	u, err := url.Parse(redirectURL)
	if err != nil {
		return "", nil, err
	}
	authURL, tokenChan, err := oauth2Callback(oic, u.Host)
	if err != nil {
		return "", nil, err
	}
	jwtChan := make(chan jose.JWT)
	go func() {
		defer close(tokenChan)
		defer close(jwtChan)
		tok := <-tokenChan
		if tok.RefreshToken == "" {
			return
		}
		for {
			jwt, err := oic.RefreshToken(tok.RefreshToken)
			if err != nil {
				return
			}
			jwtChan <- jwt
			claims, err := jwt.Claims()
			if err != nil {
				fmt.Println("claims")
				return
			}
			exp, ok, err := claims.TimeClaim("exp")
			if !ok {
				fmt.Println("time claim")
				return
			}
			// refresh 1min before expiration
			until := exp.Add(time.Duration(1) * time.Minute * -1)
			time.Sleep(until.Sub(time.Now()))
		}
	}()

	return authURL, jwtChan, nil
}

// Helper to get an OIDC client. Blocks until successful.
func GetOIDCClient(clientID, clientSecret, discoveryURL, redirectURL string) (*oidc.Client, error) {
	cc := oidc.ClientCredentials{
		ID:     clientID,
		Secret: clientSecret,
	}
	var cfg oidc.ProviderConfig
	var err error
	cfg = oidc.WaitForProviderConfig(http.DefaultClient, discoveryURL)
	ccfg := oidc.ClientConfig{
		ProviderConfig: cfg,
		Credentials:    cc,
		RedirectURL:    redirectURL,
		Scope:          []string{"offline_access", "openid", "email", "profile"},
	}
	oidcClient, err := oidc.NewClient(ccfg)
	if err != nil {
		return nil, err
	}
	oidcClient.SyncProviderConfig(discoveryURL)
	return oidcClient, nil
}
