package main

import (
	"context"
	"fmt"
	"time"

	"prism/internal/controller"
	"prism/internal/router"

	pb "prism/api/proto/control"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

const (
	defaultControllerAddr = "127.0.0.1:9090"
	userControllerTimeout = 10 * time.Second
)

type userDialConfig struct {
	Address    string
	ConfigPath string
	CACert     string
	ClientCert string
	ClientKey  string
}

type userFlagSet map[string]*string

func newUserDialFlagSet(cfg *userDialConfig) userFlagSet {
	return userFlagSet{
		"--controller":  &cfg.Address,
		"--config":      &cfg.ConfigPath,
		"--ca-cert":     &cfg.CACert,
		"--client-cert": &cfg.ClientCert,
		"--client-key":  &cfg.ClientKey,
	}
}

func (s userFlagSet) add(name string, target *string) userFlagSet {
	s[name] = target
	return s
}

func parseUserFlags(args []string, flags userFlagSet) error {
	for i := 0; i < len(args); i += 2 {
		flagName := args[i]
		target, ok := flags[flagName]
		if !ok {
			return fmt.Errorf("unknown flag: %s", flagName)
		}
		if i+1 >= len(args) {
			return fmt.Errorf("missing value for %s", flagName)
		}
		*target = args[i+1]
	}
	return nil
}

func runUser(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: prism --mode user <create|list|revoke> [options]")
	}

	switch args[0] {
	case "create":
		return runUserCreate(args[1:])
	case "list":
		return runUserList(args[1:])
	case "revoke":
		return runUserRevoke(args[1:])
	default:
		return fmt.Errorf("unknown user sub-command: %s", args[0])
	}
}

func resolveUserDialTarget(cfg userDialConfig) (string, credentials.TransportCredentials, error) {
	addr := cfg.Address
	caCert := cfg.CACert
	clientCert := cfg.ClientCert
	clientKey := cfg.ClientKey

	if cfg.ConfigPath != "" {
		prismCfg, err := LoadConfig(cfg.ConfigPath)
		if err != nil {
			return "", nil, fmt.Errorf("load config: %w", err)
		}
		if addr == "" {
			addr = prismCfg.Node.Controller
		}
		if caCert == "" {
			caCert = prismCfg.Node.MTLS.CACert
		}
		if clientCert == "" {
			clientCert = prismCfg.Node.MTLS.ClientCert
		}
		if clientKey == "" {
			clientKey = prismCfg.Node.MTLS.ClientKey
		}
	}

	if addr == "" {
		addr = defaultControllerAddr
	}
	if caCert == "" || clientCert == "" || clientKey == "" {
		return "", nil, fmt.Errorf("controller mTLS requires --ca-cert, --client-cert, and --client-key or --config with node.mtls.*")
	}

	creds, err := loadGRPCMTLSClientCredentials(caCert, clientCert, clientKey)
	if err != nil {
		return "", nil, fmt.Errorf("load controller mTLS credentials: %w", err)
	}

	return addr, creds, nil
}

func dialController(cfg userDialConfig) (*grpc.ClientConn, error) {
	addr, creds, err := resolveUserDialTarget(cfg)
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
}

func runUserCreate(args []string) error {
	var name, token, filePath string
	dialCfg := userDialConfig{}
	flags := newUserDialFlagSet(&dialCfg).
		add("--name", &name).
		add("--token", &token).
		add("--file", &filePath)
	if err := parseUserFlags(args, flags); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("--name is required")
	}

	// File-based mode: append to YAML file (standalone).
	if filePath != "" {
		return runUserCreateFile(name, token, filePath)
	}

	// gRPC mode: create via controller.
	conn, err := dialController(dialCfg)
	if err != nil {
		return fmt.Errorf("dial controller: %w", err)
	}
	defer conn.Close()

	client := pb.NewUserAuditClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), userControllerTimeout)
	defer cancel()

	resp, err := client.CreateUser(ctx, &pb.CreateUserRequest{
		UserId: name,
		Name:   name,
		Token:  token,
	})
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	u := resp.GetUser()
	fmt.Printf("User created:\n")
	fmt.Printf("  UserID:  %s\n", u.GetUserId())
	fmt.Printf("  Name:    %s\n", u.GetName())
	fmt.Printf("  Hash:    %s\n", u.GetHash())
	fmt.Printf("  Active:  %v\n", u.GetActive())
	return nil
}

func runUserCreateFile(name, token, filePath string) error {
	hash := controller.GenerateUserHash(name, "prism")
	active := true
	entry := router.UserFileEntry{
		ID:     name,
		Hash:   hash,
		Token:  token,
		Active: &active,
	}

	if err := router.AppendUser(filePath, entry); err != nil {
		return fmt.Errorf("append user to file: %w", err)
	}

	fmt.Printf("User created:\n")
	fmt.Printf("  UserID:  %s\n", name)
	fmt.Printf("  Name:    %s\n", name)
	fmt.Printf("  Hash:    %s\n", hash)
	fmt.Printf("  Active:  true\n")
	fmt.Printf("  File:    %s\n", filePath)
	return nil
}

func runUserList(args []string) error {
	dialCfg := userDialConfig{}
	if err := parseUserFlags(args, newUserDialFlagSet(&dialCfg)); err != nil {
		return err
	}

	conn, err := dialController(dialCfg)
	if err != nil {
		return fmt.Errorf("dial controller: %w", err)
	}
	defer conn.Close()

	client := pb.NewUserAuditClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), userControllerTimeout)
	defer cancel()

	resp, err := client.ListUsers(ctx, &pb.ListUsersRequest{})
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	if len(resp.GetUsers()) == 0 {
		fmt.Println("No users found.")
		return nil
	}

	fmt.Printf("%-20s %-20s %-14s %-8s %s\n", "USER_ID", "NAME", "HASH", "ACTIVE", "CREATED_AT")
	for _, u := range resp.GetUsers() {
		created := time.Unix(u.GetCreatedAt(), 0).Format("2006-01-02 15:04")
		fmt.Printf("%-20s %-20s %-14s %-8v %s\n",
			u.GetUserId(), u.GetName(), u.GetHash(), u.GetActive(), created)
	}
	return nil
}

func runUserRevoke(args []string) error {
	var userID string
	dialCfg := userDialConfig{}
	if err := parseUserFlags(args, newUserDialFlagSet(&dialCfg).add("--id", &userID)); err != nil {
		return err
	}
	if userID == "" {
		return fmt.Errorf("--id is required")
	}

	conn, err := dialController(dialCfg)
	if err != nil {
		return fmt.Errorf("dial controller: %w", err)
	}
	defer conn.Close()

	client := pb.NewUserAuditClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), userControllerTimeout)
	defer cancel()

	_, err = client.UpdateUser(ctx, &pb.UpdateUserRequest{
		UserId: userID,
		Active: proto.Bool(false),
	})
	if err != nil {
		return fmt.Errorf("revoke user: %w", err)
	}

	fmt.Printf("User %q revoked (deactivated).\n", userID)
	return nil
}
