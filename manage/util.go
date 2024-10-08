package manage

import (
	"net/url"
	"strings"

	"github.com/jzlover/go-oauth2"
	"github.com/jzlover/go-oauth2/errors"
)

type (
	// ValidateURIHandler validates that redirectURI is contained in baseURI
	ValidateURIHandler      func(baseURI, redirectURI string) error
	ExtractExtensionHandler func(*oauth2.TokenGenerateRequest, oauth2.ExtendableTokenInfo)

	GenerateSignHandler func(*oauth2.GenerateBasic) (string, error)
)

// DefaultValidateURI validates that redirectURI is contained in baseURI
func DefaultValidateURI(baseURI string, redirectURI string) error {
	base, err := url.Parse(baseURI)
	if err != nil {
		return err
	}

	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(redirect.Host, base.Host) {
		return errors.ErrInvalidRedirectURI
	}
	return nil
}

func ContainsGrantType(arr []oauth2.GrantType, data oauth2.GrantType) bool {
	for _, a := range arr {
		if a == data {
			return true
		}
	}
	return false
}
