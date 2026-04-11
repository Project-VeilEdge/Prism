package gateway

import (
	"crypto/tls"
	"fmt"

	"prism/internal/ech"
)

func buildECHKeysForOuterSNI(ks *ech.KeySet, outerSNI string) ([]tls.EncryptedClientHelloKey, error) {
	if ks == nil || ks.Current == nil {
		return nil, fmt.Errorf("gateway: current ECH key is required")
	}

	currentConfig, err := ech.ConfigForPublicName(ks.Current, outerSNI)
	if err != nil {
		return nil, fmt.Errorf("gateway: current ECH config: %w", err)
	}

	keys := []tls.EncryptedClientHelloKey{{
		Config:      currentConfig,
		PrivateKey:  append([]byte(nil), ks.Current.PrivateKey()...),
		SendAsRetry: true,
	}}

	if ks.Previous != nil {
		previousConfig, err := ech.ConfigForPublicName(ks.Previous, outerSNI)
		if err != nil {
			return nil, fmt.Errorf("gateway: previous ECH config: %w", err)
		}
		keys = append(keys, tls.EncryptedClientHelloKey{
			Config:      previousConfig,
			PrivateKey:  append([]byte(nil), ks.Previous.PrivateKey()...),
			SendAsRetry: true,
		})
	}

	return keys, nil
}
