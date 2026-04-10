package main

import (
	"context"
	"fmt"
	"time"

	pb "prism/api/proto/control"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func runQuery(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: prism --mode query <traffic> [options]")
	}

	switch args[0] {
	case "traffic":
		return runQueryTraffic(args[1:])
	default:
		return fmt.Errorf("unknown query sub-command: %s", args[0])
	}
}

func runQueryTraffic(args []string) error {
	var userID, domain, fromStr, toStr, addr string
	for i := 0; i < len(args)-1; i += 2 {
		switch args[i] {
		case "--user":
			userID = args[i+1]
		case "--domain":
			domain = args[i+1]
		case "--from":
			fromStr = args[i+1]
		case "--to":
			toStr = args[i+1]
		case "--controller":
			addr = args[i+1]
		}
	}

	req := &pb.TrafficQueryRequest{
		UserId: userID,
		Domain: domain,
	}

	if fromStr != "" {
		t, err := parseTime(fromStr)
		if err != nil {
			return fmt.Errorf("parse --from: %w", err)
		}
		req.StartTime = t.Unix()
	}
	if toStr != "" {
		t, err := parseTime(toStr)
		if err != nil {
			return fmt.Errorf("parse --to: %w", err)
		}
		req.EndTime = t.Unix()
	}

	if addr == "" {
		addr = defaultControllerAddr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial controller: %w", err)
	}
	defer conn.Close()

	client := pb.NewTrafficQueryClient(conn)
	resp, err := client.QueryTraffic(ctx, req)
	if err != nil {
		return fmt.Errorf("query traffic: %w", err)
	}

	if len(resp.GetSummaries()) == 0 {
		fmt.Println("No traffic data found.")
		return nil
	}

	fmt.Printf("%-20s %-30s %-12s %15s %15s %8s\n",
		"USER_ID", "DOMAIN", "EGRESS", "BYTES_UP", "BYTES_DOWN", "COUNT")
	for _, s := range resp.GetSummaries() {
		fmt.Printf("%-20s %-30s %-12s %15d %15d %8d\n",
			s.GetUserId(), s.GetDomain(), s.GetEgress(),
			s.GetBytesUp(), s.GetBytesDown(), s.GetCount())
	}
	return nil
}

// parseTime parses common time formats.
func parseTime(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time format: %q (use RFC3339 or YYYY-MM-DD)", s)
}
