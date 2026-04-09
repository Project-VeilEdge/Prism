package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	pb "prism/api/proto/control"
	"prism/internal/config"
	"prism/internal/ech"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// SyncClient connects to the Controller via gRPC, watches for config
// updates, and applies them to a HotConfig. On disconnect, it uses
// exponential backoff (1s..60s) and falls back to the local cache.
type SyncClient struct {
	nodeID      string
	target      string // controller address host:port
	creds       credentials.TransportCredentials
	hot         *config.HotConfig
	cachePath   string // local JSON cache file path
	publicName  string
	onRouting   func(*pb.RoutingConfig) error
	onEgressIPs func(*config.EgressIPConfig) error
	onECHKeys   func(*ech.KeySet) error

	stateMu sync.RWMutex
	routing *pb.RoutingConfig
	echKeys *pb.ECHKeyConfig

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// SyncClientConfig holds constructor parameters.
type SyncClientConfig struct {
	NodeID      string
	Target      string
	Creds       credentials.TransportCredentials
	Hot         *config.HotConfig
	CachePath   string // e.g. "/var/lib/prism/config-cache.json"
	PublicName  string
	OnRouting   func(*pb.RoutingConfig) error
	OnEgressIPs func(*config.EgressIPConfig) error
	OnECHKeys   func(*ech.KeySet) error
}

// NewSyncClient creates a new SyncClient. Call Start() to begin watching.
func NewSyncClient(cfg SyncClientConfig) *SyncClient {
	return &SyncClient{
		nodeID:      cfg.NodeID,
		target:      cfg.Target,
		creds:       cfg.Creds,
		hot:         cfg.Hot,
		cachePath:   cfg.CachePath,
		publicName:  cfg.PublicName,
		onRouting:   cfg.OnRouting,
		onEgressIPs: cfg.OnEgressIPs,
		onECHKeys:   cfg.OnECHKeys,
	}
}

// Start begins the background config watch loop.
func (sc *SyncClient) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	sc.cancel = cancel
	sc.wg.Add(1)
	go sc.watchLoop(ctx)
}

// Stop gracefully stops the background goroutine.
func (sc *SyncClient) Stop() {
	if sc.cancel != nil {
		sc.cancel()
	}
	sc.wg.Wait()
}

// LoadCache loads the local cache file into HotConfig.
// Used at startup to bootstrap HotConfig before the controller connects.
func (sc *SyncClient) LoadCache() error {
	if sc.cachePath == "" {
		return nil
	}
	data, err := os.ReadFile(sc.cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no cache yet, not an error
		}
		return err
	}
	return sc.applyCacheData(data)
}

func (sc *SyncClient) watchLoop(ctx context.Context) {
	defer sc.wg.Done()

	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}

		connected, err := sc.connectAndWatch(ctx)
		if ctx.Err() != nil {
			return
		}

		if connected {
			// Stream was established; reset backoff for next disconnect.
			attempt = 0
		}

		attempt++
		backoff := calcBackoff(attempt)
		slog.Warn("config_watch_disconnected", "err", err, "retry_in", backoff)

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
	}
}

func (sc *SyncClient) connectAndWatch(ctx context.Context) (connected bool, err error) {
	if sc.creds == nil {
		return false, fmt.Errorf("config sync requires mTLS credentials")
	}

	opts := []grpc.DialOption{}
	opts = append(opts, grpc.WithTransportCredentials(sc.creds))

	conn, err := grpc.NewClient(sc.target, opts...)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	client := pb.NewConfigSyncClient(conn)
	stream, err := client.WatchConfig(ctx, &pb.WatchConfigRequest{
		NodeId:        sc.nodeID,
		ConfigVersion: sc.hot.ConfigVersion(),
	})
	if err != nil {
		return false, err
	}

	slog.Info("config_watch_connected", "target", sc.target, "from_version", sc.hot.ConfigVersion())

	for {
		update, err := stream.Recv()
		if err != nil {
			return true, err
		}
		if err := sc.applyUpdate(update); err != nil {
			slog.Error("config_update_apply_failed",
				"version", update.GetVersion(),
				"type", update.GetConfigType().String(),
				"err", err,
			)
		}
	}
}

func (sc *SyncClient) applyUpdate(update *pb.ConfigUpdate) error {
	slog.Info("config_update_received",
		"version", update.Version,
		"type", update.ConfigType.String(),
	)

	switch update.ConfigType {
	case pb.ConfigType_CONFIG_TYPE_WHITELIST:
		if wl := update.GetWhitelist(); wl != nil {
			sc.hot.SwapWhitelist(config.NewWhitelist(wl.Domains))
		}
	case pb.ConfigType_CONFIG_TYPE_ROUTING:
		if routing := update.GetRouting(); routing != nil {
			cloned := proto.Clone(routing).(*pb.RoutingConfig)
			if sc.onRouting != nil {
				if err := sc.onRouting(cloned); err != nil {
					return fmt.Errorf("apply routing update: %w", err)
				}
			}
			sc.setRoutingSnapshot(cloned)
		}
	case pb.ConfigType_CONFIG_TYPE_USERS:
		if ul := update.GetUsers(); ul != nil {
			entries := make([]*config.UserEntry, 0, len(ul.Users))
			for _, u := range ul.Users {
				entries = append(entries, &config.UserEntry{
					UserID:    u.UserId,
					Name:      u.Name,
					Hash:      u.Hash,
					Token:     u.Token,
					Active:    u.Active,
					CreatedAt: u.CreatedAt,
				})
			}
			sc.hot.SwapUsers(config.NewUserRegistry(entries))
		}
	case pb.ConfigType_CONFIG_TYPE_EGRESS_IPS:
		if eip := update.GetEgressIps(); eip != nil {
			current := &config.EgressIPConfig{
				IPs:   append([]string(nil), eip.Ips...),
				CIDRs: append([]string(nil), eip.Cidrs...),
			}
			sc.hot.SwapEgressIPs(current)
			if sc.onEgressIPs != nil {
				if err := sc.onEgressIPs(current); err != nil {
					return fmt.Errorf("apply egress allowlist update: %w", err)
				}
			}
		}
	case pb.ConfigType_CONFIG_TYPE_ECH_KEYS:
		if echKeys := update.GetEchKeys(); echKeys != nil {
			current, err := sc.loadECHKeySet(echKeys)
			if err != nil {
				return fmt.Errorf("apply ECH keys: %w", err)
			}
			sc.hot.SwapKeySet(current)
			if sc.onECHKeys != nil {
				if err := sc.onECHKeys(current); err != nil {
					return fmt.Errorf("apply ECH key callback: %w", err)
				}
			}
			sc.setECHKeySnapshot(echKeys)
		}
	}

	sc.hot.SetConfigVersion(update.Version)
	sc.saveCache()
	return nil
}

// calcBackoff returns exponential backoff duration capped at 60s
// with ±25% jitter to prevent thundering-herd on mass reconnect.
func calcBackoff(attempt int) time.Duration {
	base := 1.0
	max := 60.0
	d := base * math.Pow(2, float64(attempt-1))
	if d > max {
		d = max
	}
	// Add jitter: multiply by [0.75, 1.25)
	jitter := 0.75 + rand.Float64()*0.5
	d *= jitter
	return time.Duration(d * float64(time.Second))
}

// --- Local cache ---

// cacheData is the JSON structure for the local config cache.
type cacheData struct {
	Version   uint64                 `json:"version"`
	Whitelist []string               `json:"whitelist,omitempty"`
	Users     []cacheUser            `json:"users,omitempty"`
	EgressIPs *config.EgressIPConfig `json:"egress_ips,omitempty"`
	Routing   *cacheRouting          `json:"routing,omitempty"`
	ECHKeys   *cacheECHKeys          `json:"ech_keys,omitempty"`
}

type cacheUser struct {
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	Hash      string `json:"hash"`
	Token     string `json:"token"`
	Active    bool   `json:"active"`
	CreatedAt int64  `json:"created_at"`
}

type cacheRouting struct {
	Nodes []cacheEgressNode  `json:"nodes,omitempty"`
	Rules []cacheRoutingRule `json:"rules,omitempty"`
}

type cacheEgressNode struct {
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`
}

type cacheRoutingRule struct {
	Domain    string   `json:"domain,omitempty"`
	CIDRs     []string `json:"cidrs,omitempty"`
	Countries []string `json:"countries,omitempty"`
	Default   bool     `json:"default,omitempty"`
	Egress    string   `json:"egress"`
}

type cacheECHKeys struct {
	CurrentPrivateKeyPEM  []byte `json:"current_private_key_pem,omitempty"`
	CurrentConfigID       uint32 `json:"current_config_id,omitempty"`
	PreviousPrivateKeyPEM []byte `json:"previous_private_key_pem,omitempty"`
	PreviousConfigID      uint32 `json:"previous_config_id,omitempty"`
	ECHConfigList         []byte `json:"ech_config_list,omitempty"`
}

func (sc *SyncClient) saveCache() {
	if sc.cachePath == "" {
		return
	}

	wl := sc.hot.Whitelist()
	users := sc.hot.Users()
	eip := sc.hot.EgressIPs()

	data := cacheData{
		Version:   sc.hot.ConfigVersion(),
		Whitelist: wl.Domains(),
		EgressIPs: eip,
		Routing:   cacheRoutingFromProto(sc.routingSnapshot()),
		ECHKeys:   cacheECHKeysFromProto(sc.echKeySnapshot()),
	}

	if users != nil {
		for _, u := range users.All() {
			data.Users = append(data.Users, cacheUser{
				UserID: u.UserID, Name: u.Name, Hash: u.Hash,
				Token: u.Token, Active: u.Active, CreatedAt: u.CreatedAt,
			})
		}
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		slog.Error("cache_marshal_failed", "err", err)
		return
	}
	if err := os.WriteFile(sc.cachePath, b, 0600); err != nil {
		slog.Error("cache_write_failed", "err", err)
	}
}

func (sc *SyncClient) applyCacheData(raw []byte) error {
	var data cacheData
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}

	if len(data.Whitelist) > 0 {
		sc.hot.SwapWhitelist(config.NewWhitelist(data.Whitelist))
	}

	if len(data.Users) > 0 {
		entries := make([]*config.UserEntry, 0, len(data.Users))
		for _, u := range data.Users {
			entries = append(entries, &config.UserEntry{
				UserID: u.UserID, Name: u.Name, Hash: u.Hash,
				Token: u.Token, Active: u.Active, CreatedAt: u.CreatedAt,
			})
		}
		sc.hot.SwapUsers(config.NewUserRegistry(entries))
	}

	if data.EgressIPs != nil {
		sc.hot.SwapEgressIPs(data.EgressIPs)
		if sc.onEgressIPs != nil {
			if err := sc.onEgressIPs(data.EgressIPs); err != nil {
				return err
			}
		}
	}

	if data.Routing != nil {
		routing := data.Routing.toProto()
		if sc.onRouting != nil {
			if err := sc.onRouting(routing); err != nil {
				return err
			}
		}
		sc.setRoutingSnapshot(routing)
	}

	if data.ECHKeys != nil {
		echKeys := data.ECHKeys.toProto()
		current, err := sc.loadECHKeySet(echKeys)
		if err != nil {
			return err
		}
		sc.hot.SwapKeySet(current)
		if sc.onECHKeys != nil {
			if err := sc.onECHKeys(current); err != nil {
				return err
			}
		}
		sc.setECHKeySnapshot(echKeys)
	}

	sc.hot.SetConfigVersion(data.Version)
	return nil
}

func (sc *SyncClient) setRoutingSnapshot(routing *pb.RoutingConfig) {
	sc.stateMu.Lock()
	defer sc.stateMu.Unlock()
	if routing == nil {
		sc.routing = nil
		return
	}
	sc.routing = proto.Clone(routing).(*pb.RoutingConfig)
}

func (sc *SyncClient) routingSnapshot() *pb.RoutingConfig {
	sc.stateMu.RLock()
	defer sc.stateMu.RUnlock()
	if sc.routing == nil {
		return nil
	}
	return proto.Clone(sc.routing).(*pb.RoutingConfig)
}

func (sc *SyncClient) setECHKeySnapshot(echKeys *pb.ECHKeyConfig) {
	sc.stateMu.Lock()
	defer sc.stateMu.Unlock()
	if echKeys == nil {
		sc.echKeys = nil
		return
	}
	sc.echKeys = proto.Clone(echKeys).(*pb.ECHKeyConfig)
}

func (sc *SyncClient) echKeySnapshot() *pb.ECHKeyConfig {
	sc.stateMu.RLock()
	defer sc.stateMu.RUnlock()
	if sc.echKeys == nil {
		return nil
	}
	return proto.Clone(sc.echKeys).(*pb.ECHKeyConfig)
}

func (sc *SyncClient) loadECHKeySet(echKeys *pb.ECHKeyConfig) (*ech.KeySet, error) {
	if echKeys == nil {
		return nil, fmt.Errorf("missing ECH key payload")
	}
	if sc.publicName == "" {
		return nil, fmt.Errorf("public name required")
	}
	if len(echKeys.GetCurrentPrivateKeyPem()) == 0 {
		return nil, fmt.Errorf("current private key is required")
	}
	return ech.LoadKeySetFromPEM(
		echKeys.GetCurrentPrivateKeyPem(),
		echKeys.GetPreviousPrivateKeyPem(),
		sc.publicName,
	)
}

func cacheRoutingFromProto(cfg *pb.RoutingConfig) *cacheRouting {
	if cfg == nil {
		return nil
	}

	out := &cacheRouting{
		Nodes: make([]cacheEgressNode, 0, len(cfg.GetNodes())),
		Rules: make([]cacheRoutingRule, 0, len(cfg.GetRules())),
	}

	for _, node := range cfg.GetNodes() {
		out.Nodes = append(out.Nodes, cacheEgressNode{
			Name:    node.GetName(),
			Address: node.GetAddress(),
		})
	}

	for _, rule := range cfg.GetRules() {
		current := cacheRoutingRule{Egress: rule.GetEgressNode()}
		switch match := rule.GetMatch().(type) {
		case *pb.RoutingRuleProto_Domain:
			current.Domain = match.Domain
		case *pb.RoutingRuleProto_Cidr:
			current.CIDRs = append([]string(nil), match.Cidr.GetCidrs()...)
		case *pb.RoutingRuleProto_Geoip:
			current.Countries = append([]string(nil), match.Geoip.GetCountries()...)
		case *pb.RoutingRuleProto_IsDefault:
			current.Default = match.IsDefault
		}
		out.Rules = append(out.Rules, current)
	}

	return out
}

func cacheECHKeysFromProto(cfg *pb.ECHKeyConfig) *cacheECHKeys {
	if cfg == nil {
		return nil
	}
	return &cacheECHKeys{
		CurrentPrivateKeyPEM:  append([]byte(nil), cfg.GetCurrentPrivateKeyPem()...),
		CurrentConfigID:       cfg.GetCurrentConfigId(),
		PreviousPrivateKeyPEM: append([]byte(nil), cfg.GetPreviousPrivateKeyPem()...),
		PreviousConfigID:      cfg.GetPreviousConfigId(),
		ECHConfigList:         append([]byte(nil), cfg.GetEchConfigList()...),
	}
}

func (c *cacheRouting) toProto() *pb.RoutingConfig {
	if c == nil {
		return nil
	}

	out := &pb.RoutingConfig{
		Nodes: make([]*pb.EgressNodeProto, 0, len(c.Nodes)),
		Rules: make([]*pb.RoutingRuleProto, 0, len(c.Rules)),
	}

	for _, node := range c.Nodes {
		out.Nodes = append(out.Nodes, &pb.EgressNodeProto{
			Name:    node.Name,
			Address: node.Address,
		})
	}

	for _, rule := range c.Rules {
		current := &pb.RoutingRuleProto{
			EgressNode: rule.Egress,
		}
		switch {
		case rule.Domain != "":
			current.Match = &pb.RoutingRuleProto_Domain{Domain: rule.Domain}
		case len(rule.CIDRs) > 0:
			current.Match = &pb.RoutingRuleProto_Cidr{
				Cidr: &pb.CIDRMatch{Cidrs: append([]string(nil), rule.CIDRs...)},
			}
		case len(rule.Countries) > 0:
			current.Match = &pb.RoutingRuleProto_Geoip{
				Geoip: &pb.GeoIPMatch{Countries: append([]string(nil), rule.Countries...)},
			}
		case rule.Default:
			current.Match = &pb.RoutingRuleProto_IsDefault{IsDefault: true}
		}
		out.Rules = append(out.Rules, current)
	}

	return out
}

func (c *cacheECHKeys) toProto() *pb.ECHKeyConfig {
	if c == nil {
		return nil
	}
	return &pb.ECHKeyConfig{
		CurrentPrivateKeyPem:  append([]byte(nil), c.CurrentPrivateKeyPEM...),
		CurrentConfigId:       c.CurrentConfigID,
		PreviousPrivateKeyPem: append([]byte(nil), c.PreviousPrivateKeyPEM...),
		PreviousConfigId:      c.PreviousConfigID,
		EchConfigList:         append([]byte(nil), c.ECHConfigList...),
	}
}
