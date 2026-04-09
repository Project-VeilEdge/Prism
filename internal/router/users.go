package router

import (
	"fmt"
	"os"
	"time"

	"prism/internal/config"
	"prism/internal/controller"

	"gopkg.in/yaml.v3"
)

// UsersFileConfig is the top-level structure of the users YAML file.
type UsersFileConfig struct {
	Users []UserFileEntry `yaml:"users"`
}

// UserFileEntry is a single user entry in the users YAML file.
type UserFileEntry struct {
	ID     string `yaml:"id"`
	Hash   string `yaml:"hash,omitempty"`   // optional — computed from id+salt if omitted
	Token  string `yaml:"token,omitempty"`  // optional bearer token
	Active *bool  `yaml:"active,omitempty"` // defaults to true if omitted
}

// isActive returns whether the user is active (defaults to true).
func (e *UserFileEntry) isActive() bool {
	if e.Active == nil {
		return true
	}
	return *e.Active
}

// LoadUsersFile reads a users YAML file and builds a UserRegistry.
// If a user entry omits the hash field, it is computed via
// GenerateUserHash(id, salt).
func LoadUsersFile(path, salt string) (*config.UserRegistry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read users file: %w", err)
	}

	var cfg UsersFileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}

	entries := make([]*config.UserEntry, 0, len(cfg.Users))
	for _, u := range cfg.Users {
		if u.ID == "" {
			continue
		}
		hash := u.Hash
		if hash == "" {
			hash = controller.GenerateUserHash(u.ID, salt)
		}
		entries = append(entries, &config.UserEntry{
			UserID:    u.ID,
			Name:      u.ID,
			Hash:      hash,
			Token:     u.Token,
			Active:    u.isActive(),
			CreatedAt: time.Now().Unix(),
		})
	}

	return config.NewUserRegistry(entries), nil
}

// AppendUser reads the users YAML file, appends a new entry, and writes it back.
// If the file does not exist, it is created.
func AppendUser(path string, entry UserFileEntry) error {
	var cfg UsersFileConfig

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read users file: %w", err)
	}
	if err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse users file: %w", err)
		}
	}

	cfg.Users = append(cfg.Users, entry)

	out, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal users file: %w", err)
	}

	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write users file: %w", err)
	}
	return nil
}
