package ech

import (
	"fmt"
	"log/slog"
	"os"
)

// LoadKeySet loads an ECH key pair from a PEM file and builds the ECHConfig.
// publicName is used for the ECHConfig's public_name field.
func LoadKeySet(keyPath, publicName string) (*KeySet, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	kp, err := ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	BuildECHConfig(kp, publicName)

	ks := &KeySet{Current: kp}
	if err := ks.SelfTest(); err != nil {
		return nil, fmt.Errorf("self-test: %w", err)
	}
	return ks, nil
}

// RotateKeySet performs dual-window key rotation. The new key becomes Current
// and the old Current moves to Previous. The caller must ensure the new key
// has already passed SelfTest before calling this.
//
// Dual-window guarantees: clients that cached the old ECHConfig (up to 2×TTL)
// will present the old config_id. The gateway tries Current first, then Previous.
func RotateKeySet(current *KeySet, newKeyPath, publicName string) (*KeySet, error) {
	data, err := os.ReadFile(newKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read new key file: %w", err)
	}
	newKP, err := ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parse new key: %w", err)
	}
	BuildECHConfig(newKP, publicName)

	// Build a candidate keyset with the new key as Current.
	candidate := &KeySet{
		Current:  newKP,
		Previous: current.Current, // old Current becomes Previous
	}

	if err := candidate.SelfTest(); err != nil {
		return nil, fmt.Errorf("new key self-test: %w", err)
	}

	slog.Info("ech_key_rotated",
		"new_config_id", newKP.ConfigID,
		"prev_config_id", current.Current.ConfigID,
	)

	return candidate, nil
}

// LoadKeySetFromPEM builds a KeySet from raw PEM bytes (no file I/O).
// Useful for receiving keys via gRPC push.
func LoadKeySetFromPEM(currentPEM []byte, previousPEM []byte, publicName string) (*KeySet, error) {
	cur, err := ParsePrivateKeyPEM(currentPEM)
	if err != nil {
		return nil, fmt.Errorf("parse current key: %w", err)
	}
	BuildECHConfig(cur, publicName)

	ks := &KeySet{Current: cur}

	if len(previousPEM) > 0 {
		prev, err := ParsePrivateKeyPEM(previousPEM)
		if err != nil {
			return nil, fmt.Errorf("parse previous key: %w", err)
		}
		BuildECHConfig(prev, publicName)
		ks.Previous = prev
	}

	if err := ks.SelfTest(); err != nil {
		return nil, fmt.Errorf("self-test: %w", err)
	}
	return ks, nil
}
