package models

import (
	"time"

	"github.com/jzlover/go-oauth2"
)

// Client client model
type Client struct {
	ID     string
	Secret string
	Domain string
	Public bool
	UserID string

	Authorities          []string           //角色
	TokenDuration        time.Duration      // token多久过期
	RefreshTokenDuration time.Duration      //refreshtoken多久过期
	Scopes               []string           //scope信息
	GrantTypes           []oauth2.GrantType //授权模式
}

// GetID client id
func (c *Client) GetID() string {
	return c.ID
}

// GetSecret client secret
func (c *Client) GetSecret() string {
	return c.Secret
}

// GetDomain client domain
func (c *Client) GetDomain() string {
	return c.Domain
}

// IsPublic public
func (c *Client) IsPublic() bool {
	return c.Public
}

// GetUserID user id
func (c *Client) GetUserID() string {
	return c.UserID
}

func (c *Client) GetAuthorities() []string {
	return c.Authorities
}

func (c *Client) GetTokenDuration() time.Duration {
	return c.TokenDuration
}

func (c *Client) GetRefreshTokenDuration() time.Duration {
	return c.RefreshTokenDuration
}

func (c *Client) GetScopes() []string {
	return c.Scopes
}

func (c *Client) GetGrantTypes() []oauth2.GrantType {
	return c.GrantTypes
}
