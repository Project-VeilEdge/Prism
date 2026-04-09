package controller

import (
	"context"
	"time"

	pb "prism/api/proto/control"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Aggregator implements the TrafficQuery gRPC service, using the Store's
// QueryTraffic method for SQL GROUP BY aggregation queries.
type Aggregator struct {
	pb.UnimplementedTrafficQueryServer
	store Store
}

// NewAggregator creates an Aggregator backed by the given Store.
func NewAggregator(store Store) *Aggregator {
	return &Aggregator{store: store}
}

// QueryTraffic handles aggregated traffic queries with optional filters
// for user_id, domain, egress, and time range.
func (a *Aggregator) QueryTraffic(ctx context.Context, req *pb.TrafficQueryRequest) (*pb.TrafficQueryResponse, error) {
	filter := TrafficQueryFilter{
		UserID: req.GetUserId(),
		Domain: req.GetDomain(),
		Egress: req.GetEgress(),
	}
	if req.GetStartTime() > 0 {
		filter.StartTime = time.Unix(req.GetStartTime(), 0)
	}
	if req.GetEndTime() > 0 {
		filter.EndTime = time.Unix(req.GetEndTime(), 0)
	}

	summaries, err := a.store.QueryTraffic(ctx, filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query traffic: %v", err)
	}

	resp := &pb.TrafficQueryResponse{
		Summaries: make([]*pb.TrafficSummary, 0, len(summaries)),
	}
	for _, s := range summaries {
		resp.Summaries = append(resp.Summaries, &pb.TrafficSummary{
			UserId:    s.UserID,
			Domain:    s.Domain,
			Egress:    s.Egress,
			BytesUp:   s.BytesUp,
			BytesDown: s.BytesDown,
			Count:     s.Count,
		})
	}
	return resp, nil
}
