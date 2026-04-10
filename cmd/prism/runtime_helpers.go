package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	pb "prism/api/proto/control"
	appconfig "prism/internal/config"
	"prism/internal/controller"
	prismdns "prism/internal/dns"
	"prism/internal/ech"
	"prism/internal/egress"
	"prism/internal/router"
	"prism/pkg/mtls"

	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

type runtimeValidator struct {
	hot              *appconfig.HotConfig
	allowHexFallback bool
}

func newRuntimeValidator(hot *appconfig.HotConfig, allowHexFallback bool) *runtimeValidator {
	return &runtimeValidator{
		hot:              hot,
		allowHexFallback: allowHexFallback,
	}
}

func bearerTokensEnabled(cfg *PrismConfig) bool {
	return cfg == nil || cfg.DNS.Auth.EnableBearerTokens == nil || *cfg.DNS.Auth.EnableBearerTokens
}

func buildRateLimiter(cfg *PrismConfig) (*prismdns.RateLimiter, time.Duration, bool, error) {
	if cfg == nil || cfg.DNS.RateLimit.Enabled == nil || !*cfg.DNS.RateLimit.Enabled {
		return nil, 0, false, nil
	}

	var (
		window      time.Duration
		cleanupTTL  time.Duration
		cleanupFreq time.Duration
		err         error
	)

	if cfg.DNS.RateLimit.Window != "" {
		window, err = time.ParseDuration(cfg.DNS.RateLimit.Window)
		if err != nil {
			return nil, 0, false, err
		}
	}
	if cfg.DNS.RateLimit.CleanupTTL != "" {
		cleanupTTL, err = time.ParseDuration(cfg.DNS.RateLimit.CleanupTTL)
		if err != nil {
			return nil, 0, false, err
		}
	}
	if cfg.DNS.RateLimit.CleanupFrequency != "" {
		cleanupFreq, err = time.ParseDuration(cfg.DNS.RateLimit.CleanupFrequency)
		if err != nil {
			return nil, 0, false, err
		}
	}

	limiter := prismdns.NewRateLimiter(prismdns.RateLimiterConfig{
		MaxRequests: cfg.DNS.RateLimit.MaxRequests,
		Window:      window,
		CleanupTTL:  cleanupTTL,
	})
	return limiter, cleanupFreq, true, nil
}

func (v *runtimeValidator) Contains(domain string) bool {
	if v == nil || v.hot == nil {
		return false
	}
	return v.hot.Whitelist().Contains(domain)
}

func (v *runtimeValidator) IsValidUser(hash string) bool {
	if v == nil || v.hot == nil {
		return false
	}

	users := v.hot.Users()
	if entry, ok := users.GetByHash(hash); ok {
		return entry.Active
	}

	return v.allowHexFallback && users.Len() == 0 && isValidHexHash(hash)
}

func (v *runtimeValidator) LookupUserID(hash string) string {
	if v == nil || v.hot == nil {
		return ""
	}

	users := v.hot.Users()
	if entry, ok := users.GetByHash(hash); ok {
		return entry.UserID
	}

	if v.allowHexFallback && users.Len() == 0 {
		return hash
	}
	return ""
}

func (v *runtimeValidator) GetUserToken(hash string) string {
	if v == nil || v.hot == nil {
		return ""
	}

	entry, ok := v.hot.Users().GetByHash(hash)
	if !ok {
		return ""
	}
	return entry.Token
}

func loadLocalHotConfig(cfg *PrismConfig) (*appconfig.HotConfig, error) {
	hot := appconfig.NewHotConfig()

	if cfg.WhitelistPath != "" {
		wl, err := loadWhitelistFromFile(cfg.WhitelistPath)
		if err != nil {
			return nil, fmt.Errorf("load whitelist %s: %w", cfg.WhitelistPath, err)
		}
		hot.SwapWhitelist(wl)
	}

	if cfg.UsersPath != "" {
		reg, err := router.LoadUsersFile(cfg.UsersPath, userSalt)
		if err != nil {
			return nil, fmt.Errorf("load users %s: %w", cfg.UsersPath, err)
		}
		hot.SwapUsers(reg)
		slog.Info("users_loaded", "path", cfg.UsersPath, "count", len(reg.All()))
	}

	if cfg.ECH.KeyPath != "" {
		ks, err := loadKeySet(cfg)
		if err != nil {
			return nil, fmt.Errorf("load ECH keys %s: %w", cfg.ECH.KeyPath, err)
		}
		hot.SwapKeySet(ks)
	}

	return hot, nil
}

func echPublicName(cfg *PrismConfig) string {
	if cfg == nil {
		return ""
	}
	if cfg.ECH.PublicName != "" {
		return cfg.ECH.PublicName
	}
	return cfg.BaseDomain
}

func seedControllerUsersFromFile(ctx context.Context, cfg *PrismConfig, store controller.Store) error {
	if cfg == nil || cfg.UsersPath == "" || store == nil {
		return nil
	}

	existing, err := store.ListUsers(ctx, false)
	if err != nil {
		return fmt.Errorf("list existing controller users: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}

	reg, err := router.LoadUsersFile(cfg.UsersPath, userSalt)
	if err != nil {
		return fmt.Errorf("load controller users %s: %w", cfg.UsersPath, err)
	}

	for _, entry := range reg.All() {
		createdAt := time.Unix(entry.CreatedAt, 0)
		if entry.CreatedAt == 0 {
			createdAt = time.Now()
		}
		if err := store.CreateUser(ctx, &controller.User{
			UserID:    entry.UserID,
			Name:      entry.Name,
			Hash:      entry.Hash,
			Token:     entry.Token,
			Active:    entry.Active,
			CreatedAt: createdAt,
		}); err != nil {
			return fmt.Errorf("seed controller user %s: %w", entry.UserID, err)
		}
	}

	slog.Info("controller_users_seeded", "path", cfg.UsersPath, "count", len(reg.All()))
	return nil
}

type routingRuntime struct {
	router   *egress.Router
	geoip    *egress.GeoIP
	mu       sync.RWMutex
	snapshot *pb.RoutingConfig
}

func newRoutingRuntime(geoipDBPath string, initial *pb.RoutingConfig) (*routingRuntime, error) {
	geoip, err := egress.NewGeoIP(geoipDBPath)
	if err != nil {
		return nil, err
	}

	runtime := &routingRuntime{
		router: egress.NewRouter(nil, geoip),
		geoip:  geoip,
	}

	if initial != nil {
		if err := runtime.Apply(initial); err != nil {
			geoip.Close()
			return nil, err
		}
	}

	return runtime, nil
}

func (r *routingRuntime) Router() *egress.Router {
	if r == nil {
		return nil
	}
	return r.router
}

func (r *routingRuntime) Apply(cfg *pb.RoutingConfig) error {
	if r == nil {
		return nil
	}
	if cfg == nil {
		cfg = &pb.RoutingConfig{}
	}

	rules, err := egress.RulesFromProto(cfg)
	if err != nil {
		return err
	}

	r.router.Reload(rules)

	r.mu.Lock()
	r.snapshot = proto.Clone(cfg).(*pb.RoutingConfig)
	r.mu.Unlock()
	return nil
}

func (r *routingRuntime) Snapshot() *pb.RoutingConfig {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.snapshot == nil {
		return nil
	}
	return proto.Clone(r.snapshot).(*pb.RoutingConfig)
}

func (r *routingRuntime) Close() error {
	if r == nil || r.geoip == nil {
		return nil
	}
	return r.geoip.Close()
}

type controllerECHState struct {
	keyPath    string
	publicName string
	store      *controller.SQLiteStore

	mu      sync.RWMutex
	current *ech.KeySet
}

func newControllerECHState(cfg *PrismConfig, store *controller.SQLiteStore) (*controllerECHState, *pb.ConfigUpdate, error) {
	if cfg == nil || cfg.ECH.KeyPath == "" {
		return nil, nil, nil
	}

	currentPEM, err := os.ReadFile(cfg.ECH.KeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read controller ECH key: %w", err)
	}

	var previousPEM []byte
	if store != nil {
		persisted, err := store.LoadECHKeyState(context.Background())
		if err != nil {
			return nil, nil, fmt.Errorf("load persisted ECH key state: %w", err)
		}
		previousPEM = selectStartupPreviousECHKey(currentPEM, persisted)
	}

	ks, err := ech.LoadKeySetFromPEM(currentPEM, previousPEM, echPublicName(cfg))
	if err != nil {
		return nil, nil, fmt.Errorf("load controller ECH keys: %w", err)
	}

	state := &controllerECHState{
		keyPath:    cfg.ECH.KeyPath,
		publicName: echPublicName(cfg),
		store:      store,
		current:    ks,
	}
	if err := state.persist(context.Background(), ks); err != nil {
		return nil, nil, fmt.Errorf("persist initial ECH key state: %w", err)
	}
	return state, echConfigUpdateFromKeySet(ks), nil
}

func (s *controllerECHState) ReloadUpdate() (*pb.ConfigUpdate, error) {
	if s == nil {
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		next *ech.KeySet
		err  error
	)
	if s.current == nil {
		next, err = ech.LoadKeySet(s.keyPath, s.publicName)
	} else {
		next, err = ech.RotateKeySet(s.current, s.keyPath, s.publicName)
	}
	if err != nil {
		return nil, err
	}

	if err := s.persist(context.Background(), next); err != nil {
		return nil, err
	}
	s.current = next
	return echConfigUpdateFromKeySet(next), nil
}

func (s *controllerECHState) persist(ctx context.Context, ks *ech.KeySet) error {
	if s == nil || s.store == nil || ks == nil || ks.Current == nil {
		return nil
	}

	state := &controller.ECHKeyState{
		CurrentPrivateKeyPEM: ks.Current.MarshalPrivateKeyPEM(),
		UpdatedAt:            time.Now(),
	}
	if ks.Previous != nil {
		state.PreviousPrivateKeyPEM = ks.Previous.MarshalPrivateKeyPEM()
	}
	if err := s.store.SaveECHKeyState(ctx, state); err != nil {
		return fmt.Errorf("save persisted ECH key state: %w", err)
	}
	return nil
}

func selectStartupPreviousECHKey(currentPEM []byte, persisted *controller.ECHKeyState) []byte {
	if len(currentPEM) == 0 || persisted == nil {
		return nil
	}

	if pemEqual(currentPEM, persisted.CurrentPrivateKeyPEM) {
		return append([]byte(nil), persisted.PreviousPrivateKeyPEM...)
	}
	return append([]byte(nil), persisted.CurrentPrivateKeyPEM...)
}

func pemEqual(a, b []byte) bool {
	return bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b))
}

func echConfigUpdateFromKeySet(ks *ech.KeySet) *pb.ConfigUpdate {
	payload := echKeyConfigFromKeySet(ks)
	if payload == nil {
		return nil
	}
	return &pb.ConfigUpdate{
		ConfigType: pb.ConfigType_CONFIG_TYPE_ECH_KEYS,
		Payload: &pb.ConfigUpdate_EchKeys{
			EchKeys: payload,
		},
	}
}

func echKeyConfigFromKeySet(ks *ech.KeySet) *pb.ECHKeyConfig {
	if ks == nil || ks.Current == nil {
		return nil
	}

	payload := &pb.ECHKeyConfig{
		CurrentPrivateKeyPem: ks.Current.MarshalPrivateKeyPEM(),
		CurrentConfigId:      uint32(ks.Current.ConfigID),
		EchConfigList:        buildECHConfigListPayload(ks),
	}
	if ks.Previous != nil {
		payload.PreviousPrivateKeyPem = ks.Previous.MarshalPrivateKeyPEM()
		payload.PreviousConfigId = uint32(ks.Previous.ConfigID)
	}
	return payload
}

func buildECHConfigListPayload(ks *ech.KeySet) []byte {
	if ks == nil {
		return nil
	}

	var totalLen int
	var configs [][]byte
	if len(ks.Current.Config) > 0 {
		configs = append(configs, ks.Current.Config)
		totalLen += len(ks.Current.Config)
	}
	if ks.Previous != nil && len(ks.Previous.Config) > 0 {
		configs = append(configs, ks.Previous.Config)
		totalLen += len(ks.Previous.Config)
	}
	if totalLen == 0 {
		return nil
	}

	out := make([]byte, 2+totalLen)
	out[0] = byte(totalLen >> 8)
	out[1] = byte(totalLen)
	offset := 2
	for _, cfg := range configs {
		copy(out[offset:], cfg)
		offset += len(cfg)
	}
	return out
}

func waitForRuntimeKeySet(ctx context.Context, hot *appconfig.HotConfig, timeout time.Duration) (*ech.KeySet, error) {
	if hot == nil {
		return nil, fmt.Errorf("hot config is required")
	}
	if ks := hot.KeySet(); ks != nil {
		return ks, nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if ks := hot.KeySet(); ks != nil {
			return ks, nil
		}

		select {
		case <-waitCtx.Done():
			return nil, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func seedControllerSnapshots(ctx context.Context, cfg *PrismConfig, store controller.Store, control *controller.ControlServer) error {
	users, err := store.ListUsers(ctx, false)
	if err != nil {
		return fmt.Errorf("seed users snapshot: %w", err)
	}
	control.BroadcastConfig(&pb.ConfigUpdate{
		ConfigType: pb.ConfigType_CONFIG_TYPE_USERS,
		Payload: &pb.ConfigUpdate_Users{
			Users: usersToProto(users),
		},
	})

	if cfg.WhitelistPath != "" {
		wl, err := loadWhitelistFromFile(cfg.WhitelistPath)
		if err != nil {
			return fmt.Errorf("seed whitelist snapshot: %w", err)
		}
		control.BroadcastConfig(&pb.ConfigUpdate{
			ConfigType: pb.ConfigType_CONFIG_TYPE_WHITELIST,
			Payload: &pb.ConfigUpdate_Whitelist{
				Whitelist: &pb.WhitelistConfig{Domains: wl.Domains()},
			},
		})
	}

	if cfg.RoutingPath != "" {
		routingCfg, err := egress.LoadRoutingFile(cfg.RoutingPath)
		if err != nil {
			return fmt.Errorf("seed routing snapshot: %w", err)
		}
		control.BroadcastConfig(&pb.ConfigUpdate{
			ConfigType: pb.ConfigType_CONFIG_TYPE_ROUTING,
			Payload: &pb.ConfigUpdate_Routing{
				Routing: routingCfg,
			},
		})
	}

	control.BroadcastConfig(&pb.ConfigUpdate{
		ConfigType: pb.ConfigType_CONFIG_TYPE_EGRESS_IPS,
		Payload: &pb.ConfigUpdate_EgressIps{
			EgressIps: &pb.EgressIPList{
				Ips:   append([]string(nil), cfg.Egress.StaticAllowIPs...),
				Cidrs: append([]string(nil), cfg.Egress.StaticAllowCIDRs...),
			},
		},
	})

	return nil
}

func usersToProto(users []*controller.User) *pb.UserList {
	list := &pb.UserList{Users: make([]*pb.UserProto, 0, len(users))}
	for _, user := range users {
		list.Users = append(list.Users, &pb.UserProto{
			UserId:    user.UserID,
			Name:      user.Name,
			Hash:      user.Hash,
			Token:     user.Token,
			Active:    user.Active,
			CreatedAt: user.CreatedAt.Unix(),
		})
	}
	return list
}

func loadMTLSClientTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	if caFile == "" || certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("ca, cert, and key paths required")
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return mtls.ClientTLSConfig(caPEM, certPEM, keyPEM)
}

func loadGRPCMTLSClientCredentials(caFile, certFile, keyFile string) (credentials.TransportCredentials, error) {
	tlsCfg, err := loadMTLSClientTLSConfig(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(tlsCfg), nil
}
