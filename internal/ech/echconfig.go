package ech

import "encoding/binary"

// ECH cipher suite constants (RFC 9180 / RFC 9849).
const (
	KEMX25519HKDFSHA256 uint16 = 0x0020 // HPKE KEM: X25519 + HKDF-SHA256
	KDFHKDFSHA256       uint16 = 0x0001 // HPKE KDF: HKDF-SHA256
	AEADAES128GCM       uint16 = 0x0001 // HPKE AEAD: AES-128-GCM
)

// echConfigVersion is the version field for ECHConfig per RFC 9849.
// This is also the extension type for the ECH extension in ClientHello.
const echConfigVersion = 0xfe0d

// BuildECHConfig serializes an ECHConfig structure and stores it in kp.Config.
//
// Wire format (RFC 9849 §4):
//
//	ECHConfig {
//	   version:  uint16        = 0xfe0d
//	   length:   uint16        = len(contents)
//	   contents: ECHConfigContents
//	}
//
//	ECHConfigContents {
//	   HpkeKeyConfig {
//	      config_id:     uint8
//	      kem_id:        uint16
//	      public_key:    <0..2^16-1>   (length-prefixed)
//	      cipher_suites: <4..2^16-4>   (length-prefixed)
//	        HpkeSymmetricCipherSuite {
//	            kdf_id:  uint16
//	            aead_id: uint16
//	        }
//	   }
//	   maximum_name_length: uint8
//	   public_name:         <1..255>    (1-byte length-prefixed)
//	   extensions:          <0..2^16-1> (2-byte length-prefixed, empty)
//	}
func BuildECHConfig(kp *KeyPair, publicName string) {
	pk := kp.PublicKey() // 32 bytes for X25519

	// --- Compute contents first to know its length ---

	// HpkeKeyConfig:
	//   config_id(1) + kem_id(2) + pk_len(2) + pk(32) + cs_len(2) + cs(4) = 43
	keyConfigLen := 1 + 2 + 2 + len(pk) + 2 + 4

	// ECHConfigContents:
	//   key_config(43) + max_name_len(1) + name_len(1) + name(N) + ext_len(2) + ext(0)
	contentsLen := keyConfigLen + 1 + 1 + len(publicName) + 2

	// ECHConfig:
	//   version(2) + length(2) + contents(N)
	totalLen := 2 + 2 + contentsLen
	buf := make([]byte, totalLen)
	off := 0

	// --- version (2 bytes) ---
	binary.BigEndian.PutUint16(buf[off:], echConfigVersion) // 0xfe0d
	off += 2

	// --- length of contents (2 bytes) ---
	binary.BigEndian.PutUint16(buf[off:], uint16(contentsLen))
	off += 2

	// --- HpkeKeyConfig ---
	// config_id (1 byte)
	buf[off] = kp.ConfigID
	off++

	// kem_id (2 bytes)
	binary.BigEndian.PutUint16(buf[off:], KEMX25519HKDFSHA256) // 0x0020
	off += 2

	// public_key length (2 bytes) + public_key (32 bytes)
	binary.BigEndian.PutUint16(buf[off:], uint16(len(pk)))
	off += 2
	copy(buf[off:], pk)
	off += len(pk)

	// cipher_suites length (2 bytes) — one suite = 4 bytes
	binary.BigEndian.PutUint16(buf[off:], 4)
	off += 2

	// cipher_suite: kdf_id (2 bytes) + aead_id (2 bytes)
	binary.BigEndian.PutUint16(buf[off:], KDFHKDFSHA256) // 0x0001
	off += 2
	binary.BigEndian.PutUint16(buf[off:], AEADAES128GCM) // 0x0001
	off += 2

	// --- maximum_name_length (1 byte) ---
	buf[off] = 0 // 0 = no padding enforcement
	off++

	// --- public_name (1-byte length prefix + name bytes) ---
	buf[off] = byte(len(publicName))
	off++
	copy(buf[off:], publicName)
	off += len(publicName)

	// --- extensions (2-byte length prefix, empty) ---
	binary.BigEndian.PutUint16(buf[off:], 0)
	// off += 2

	kp.Config = buf
}

// HPKEInfoString returns the info parameter for HPKE context:
//
//	"tls ech" || 0x00 || ECHConfig
//
// This must match between client and server for decryption to succeed.
func (kp *KeyPair) HPKEInfoString() []byte {
	prefix := []byte("tls ech\x00")
	info := make([]byte, len(prefix)+len(kp.Config))
	copy(info, prefix)
	copy(info[len(prefix):], kp.Config)
	return info
}
