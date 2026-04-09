package egress

import (
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// GeoIP provides country lookups from a MaxMind mmdb database
// with atomic hot-reload support.
type GeoIP struct {
	reader atomic.Pointer[maxminddb.Reader]
}

type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// NewGeoIP creates a new GeoIP instance. If dbPath is empty, lookups
// always return an empty string (disabled mode).
func NewGeoIP(dbPath string) (*GeoIP, error) {
	g := &GeoIP{}
	if dbPath == "" {
		return g, nil
	}
	r, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("geoip: open %s: %w", dbPath, err)
	}
	g.reader.Store(r)
	return g, nil
}

// LookupCountry returns the ISO country code for the given IP.
// Returns empty string if the database is not loaded or the IP is not found.
func (g *GeoIP) LookupCountry(ip net.IP) string {
	r := g.reader.Load()
	if r == nil {
		return ""
	}
	var rec geoRecord
	if err := r.Lookup(ip, &rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}

// Reload replaces the mmdb reader with a new one loaded from dbPath.
// The old reader is closed after a 5-second delay to avoid disrupting
// in-flight lookups.
func (g *GeoIP) Reload(dbPath string) error {
	newReader, err := maxminddb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("geoip: reload %s: %w", dbPath, err)
	}

	old := g.reader.Swap(newReader)
	if old != nil {
		go func() {
			time.Sleep(5 * time.Second)
			if err := old.Close(); err != nil {
				slog.Error("geoip: close old reader", "err", err)
			}
		}()
	}

	slog.Info("geoip_reload_ok", "path", dbPath)
	return nil
}

// Close shuts down the GeoIP reader.
func (g *GeoIP) Close() error {
	r := g.reader.Swap(nil)
	if r != nil {
		return r.Close()
	}
	return nil
}
