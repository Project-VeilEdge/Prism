package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// UserHashLength is the number of hex characters in the user hash.
const UserHashLength = 12

// GenerateUserHash computes SHA256(user_id + ":" + salt)[:12] hex string.
func GenerateUserHash(userID, salt string) string {
	h := sha256.Sum256([]byte(userID + ":" + salt))
	return hex.EncodeToString(h[:])[:UserHashLength]
}

// unixToTime converts a unix timestamp to time.Time.
func unixToTime(unix int64) time.Time {
	return time.Unix(unix, 0)
}

// NewUser constructs a User with the hash computed from user_id and salt.
func NewUser(userID, name, token, salt string) *User {
	return &User{
		UserID:    userID,
		Name:      name,
		Hash:      GenerateUserHash(userID, salt),
		Token:     token,
		Active:    true,
		CreatedAt: time.Now(),
	}
}
