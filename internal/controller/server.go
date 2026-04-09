package controller

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"log/slog"
	"sort"
	"sync"
	"time"

	pb "prism/api/proto/control"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// ControlServer implements the gRPC services: ConfigSync, NodeReport, UserAudit, DNSAudit.
type ControlServer struct {
	pb.UnimplementedConfigSyncServer
	pb.UnimplementedNodeReportServer
	pb.UnimplementedUserAuditServer
	pb.UnimplementedDNSAuditServer

	store Store
	salt  string

	// --- Config broadcast ---
	mu       sync.RWMutex
	watchers map[string]chan *pb.ConfigUpdate // node_id → channel
	version  uint64
	current  map[pb.ConfigType]*pb.ConfigUpdate
}

// NewControlServer creates a new ControlServer.
func NewControlServer(store Store, salt string) *ControlServer {
	return &ControlServer{
		store:    store,
		salt:     salt,
		watchers: make(map[string]chan *pb.ConfigUpdate),
		current:  make(map[pb.ConfigType]*pb.ConfigUpdate),
	}
}

// ---------------------------------------------------------------------------
// ConfigSync
// ---------------------------------------------------------------------------

func (s *ControlServer) WatchConfig(req *pb.WatchConfigRequest, stream pb.ConfigSync_WatchConfigServer) error {
	nodeID := req.GetNodeId()
	if nodeID == "" {
		return status.Error(codes.InvalidArgument, "node_id required")
	}

	ch := make(chan *pb.ConfigUpdate, 64)

	s.mu.Lock()
	// Replace any existing watcher for this node (reconnect case).
	if old, ok := s.watchers[nodeID]; ok {
		close(old)
	}
	s.watchers[nodeID] = ch
	initial := s.snapshotUpdatesLocked(req.GetConfigVersion())
	s.mu.Unlock()

	slog.Info("config_watch_start", "node_id", nodeID, "from_version", req.GetConfigVersion())

	defer func() {
		s.mu.Lock()
		// Only delete if ch is still the current watcher for this node.
		if current, ok := s.watchers[nodeID]; ok && current == ch {
			delete(s.watchers, nodeID)
		}
		s.mu.Unlock()
		slog.Info("config_watch_end", "node_id", nodeID)
	}()

	for _, update := range initial {
		if err := stream.Send(update); err != nil {
			return err
		}
	}

	// Send updates until the stream is closed.
	for {
		select {
		case update, ok := <-ch:
			if !ok {
				// Channel closed (node reconnected or server shutting down).
				return nil
			}
			if err := stream.Send(update); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// BroadcastConfig sends a config update to all connected watchers.
func (s *ControlServer) BroadcastConfig(update *pb.ConfigUpdate) {
	stored := proto.Clone(update).(*pb.ConfigUpdate)

	s.mu.Lock()
	s.version++
	stored.Version = s.version
	s.current[stored.ConfigType] = stored
	watchers := make(map[string]chan *pb.ConfigUpdate, len(s.watchers))
	for nodeID, ch := range s.watchers {
		watchers[nodeID] = ch
	}
	s.mu.Unlock()

	for nodeID, ch := range watchers {
		select {
		case ch <- stored:
		default:
			slog.Warn("config_update_dropped", "node_id", nodeID, "version", stored.Version)
		}
	}
}

// WatcherCount returns the number of active watchers.
func (s *ControlServer) WatcherCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.watchers)
}

func (s *ControlServer) snapshotUpdatesLocked(fromVersion uint64) []*pb.ConfigUpdate {
	if len(s.current) == 0 {
		return nil
	}

	updates := make([]*pb.ConfigUpdate, 0, len(s.current))
	for _, update := range s.current {
		if update.Version <= fromVersion {
			continue
		}
		updates = append(updates, proto.Clone(update).(*pb.ConfigUpdate))
	}

	sort.Slice(updates, func(i, j int) bool {
		return updates[i].Version < updates[j].Version
	})

	return updates
}

// ---------------------------------------------------------------------------
// NodeReport
// ---------------------------------------------------------------------------

func (s *ControlServer) ReportTraffic(stream pb.NodeReport_ReportTrafficServer) error {
	var total int64
	for {
		batch, err := stream.Recv()
		if err != nil {
			// Client closed the stream.
			return stream.SendAndClose(&pb.ReportAck{Received: total})
		}

		records := make([]TrafficRecord, 0, len(batch.GetRecords()))
		for _, r := range batch.GetRecords() {
			records = append(records, TrafficRecord{
				NodeID:     batch.GetNodeId(),
				UserID:     r.GetUserId(),
				ClientIP:   r.GetClientIp(),
				Domain:     r.GetDomain(),
				Egress:     r.GetEgress(),
				BytesUp:    r.GetBytesUp(),
				BytesDown:  r.GetBytesDown(),
				StartTime:  time.Unix(r.GetStartTime(), 0),
				EndTime:    time.Unix(r.GetEndTime(), 0),
				ECHSuccess: r.GetEchSuccess(),
				ErrorType:  r.GetErrorType(),
			})
		}

		if err := s.store.InsertTraffic(stream.Context(), records); err != nil {
			slog.Error("traffic_insert_failed", "node_id", batch.GetNodeId(), "err", err)
			// Don't fail the stream — just log and continue.
		}
		total += int64(len(records))
	}
}

// ---------------------------------------------------------------------------
// DNSAudit
// ---------------------------------------------------------------------------

func (s *ControlServer) ReportDNS(stream pb.DNSAudit_ReportDNSServer) error {
	var total int64
	for {
		batch, err := stream.Recv()
		if err != nil {
			return stream.SendAndClose(&pb.DNSAuditAck{Received: total})
		}

		records := make([]DNSAuditRecord, 0, len(batch.GetRecords()))
		for _, r := range batch.GetRecords() {
			records = append(records, DNSAuditRecord{
				NodeID:    batch.GetNodeId(),
				UserID:    r.GetUserId(),
				Domain:    r.GetDomain(),
				QueryType: r.GetQueryType(),
				ClientIP:  r.GetClientIp(),
				Timestamp: time.Unix(r.GetTimestamp(), 0),
			})
		}

		if err := s.store.InsertDNSAudit(stream.Context(), records); err != nil {
			slog.Error("dns_audit_insert_failed", "node_id", batch.GetNodeId(), "err", err)
		}
		total += int64(len(records))
	}
}

// ---------------------------------------------------------------------------
// UserAudit
// ---------------------------------------------------------------------------

func (s *ControlServer) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	u := NewUser(req.GetUserId(), req.GetName(), req.GetToken(), s.salt)
	if err := s.store.CreateUser(ctx, u); err != nil {
		return nil, status.Errorf(codes.Internal, "create user: %v", err)
	}

	slog.Info("user_created", "user_id", u.UserID, "hash", u.Hash)

	// Broadcast updated user list.
	s.broadcastUsers(ctx)

	return &pb.CreateUserResponse{User: userToProto(u)}, nil
}

func (s *ControlServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserProto, error) {
	u, err := s.store.GetUser(ctx, req.GetUserId())
	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get user: %v", err)
	}
	return userToProto(u), nil
}

func (s *ControlServer) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	users, err := s.store.ListUsers(ctx, req.GetActiveOnly())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list users: %v", err)
	}
	resp := &pb.ListUsersResponse{Users: make([]*pb.UserProto, 0, len(users))}
	for _, u := range users {
		resp.Users = append(resp.Users, userToProto(u))
	}
	return resp, nil
}

func (s *ControlServer) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UserProto, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}

	existing, err := s.store.GetUser(ctx, req.GetUserId())
	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get user: %v", err)
	}

	if req.GetName() != "" {
		existing.Name = req.GetName()
	}
	if req.GetToken() != "" {
		existing.Token = req.GetToken()
	}
	if req.Active != nil {
		existing.Active = *req.Active
	}

	if err := s.store.UpdateUser(ctx, existing); err != nil {
		return nil, status.Errorf(codes.Internal, "update user: %v", err)
	}

	slog.Info("user_updated", "user_id", existing.UserID)
	s.broadcastUsers(ctx)
	return userToProto(existing), nil
}

func (s *ControlServer) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}

	if err := s.store.DeleteUser(ctx, req.GetUserId()); err != nil {
		return nil, status.Errorf(codes.Internal, "delete user: %v", err)
	}

	slog.Info("user_deleted", "user_id", req.GetUserId())
	s.broadcastUsers(ctx)
	return &pb.DeleteUserResponse{}, nil
}

func (s *ControlServer) AuthUser(ctx context.Context, req *pb.AuthUserRequest) (*pb.AuthUserResponse, error) {
	if req.GetHash() == "" {
		return &pb.AuthUserResponse{Valid: false}, nil
	}

	u, err := s.store.GetUserByHash(ctx, req.GetHash())
	if err == sql.ErrNoRows {
		return &pb.AuthUserResponse{Valid: false}, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "auth user: %v", err)
	}

	if !u.Active {
		return &pb.AuthUserResponse{Valid: false}, nil
	}

	// If token is set on the user, validate it (constant-time to prevent timing attacks).
	if u.Token != "" && subtle.ConstantTimeCompare([]byte(req.GetToken()), []byte(u.Token)) != 1 {
		return &pb.AuthUserResponse{Valid: false}, nil
	}

	return &pb.AuthUserResponse{Valid: true, User: userToProto(u)}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *ControlServer) broadcastUsers(ctx context.Context) {
	users, err := s.store.ListUsers(ctx, false)
	if err != nil {
		slog.Error("broadcast_users_list_failed", "err", err)
		return
	}
	protos := make([]*pb.UserProto, 0, len(users))
	for _, u := range users {
		protos = append(protos, userToProto(u))
	}
	s.BroadcastConfig(&pb.ConfigUpdate{
		ConfigType: pb.ConfigType_CONFIG_TYPE_USERS,
		Payload:    &pb.ConfigUpdate_Users{Users: &pb.UserList{Users: protos}},
	})
}

func userToProto(u *User) *pb.UserProto {
	return &pb.UserProto{
		UserId:    u.UserID,
		Name:      u.Name,
		Hash:      u.Hash,
		Token:     u.Token,
		Active:    u.Active,
		CreatedAt: u.CreatedAt.Unix(),
	}
}
