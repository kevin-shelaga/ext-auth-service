package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// Config matches your YAML structure
type Config struct {
	Departments []struct {
		Name  string   `yaml:"name"`
		CIDRs []string `yaml:"cidrs"`
	} `yaml:"departments"`
}

type CIDRBlock struct {
	Department string
	Net        *net.IPNet
}

type ExtAuthServer struct {
	authv3.UnimplementedAuthorizationServer
	cidrs []CIDRBlock
}

// LoadCIDRs reads and parses CIDRs from a YAML file
func LoadCIDRs(path string) ([]CIDRBlock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	var cidrs []CIDRBlock
	for _, dept := range cfg.Departments {
		for _, cidr := range dept.CIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR '%s': %w", cidr, err)
			}
			cidrs = append(cidrs, CIDRBlock{
				Department: dept.Name,
				Net:        ipnet,
			})
		}
	}

	return cidrs, nil
}

func watchConfig(path string, reload func()) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			log.Printf("Failed to close watcher: %v", err)
		}
	}()

	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		log.Fatalf("Failed to watch directory: %v", err)
	}

	debounce := time.NewTimer(time.Hour)
	debounce.Stop()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			log.Printf("FS event: %s %s", event.Op, event.Name)
			// Any event in the directory triggers debounce
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
				debounce.Reset(500 * time.Millisecond) // wait before reload
			}
		case <-debounce.C:
			// Ensure file exists and is readable
			if _, err := os.Stat(path); err == nil {
				reload()
			} else {
				log.Printf("Config file not ready: %v", err)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func (s *ExtAuthServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	sourceAddr := req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress()
	if sourceAddr == "" {
		log.Printf("Missing source address in request attributes")
		return deny("missing source address")
	}

	ip := net.ParseIP(sourceAddr)
	if ip == nil {
		log.Printf("Invalid IP format: %s", sourceAddr)
		return deny("invalid IP format")
	}

	for _, block := range s.cidrs {
		if block.Net.Contains(ip) {
			log.Printf("Allowed IP %s matched department: %s", ip, block.Department)
			return allow()
		}
	}

	log.Printf("Denied IP %s - no matching CIDR", ip)
	return deny(fmt.Sprintf("IP %s not allowed", ip))
}

func allow() (*authv3.CheckResponse, error) {
	return &authv3.CheckResponse{
		Status: &statuspb.Status{Code: 0}, // OK
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "x-ext-authz",
							Value: "authorized",
						},
					},
				},
			},
		},
	}, nil
}

func deny(reason string) (*authv3.CheckResponse, error) {
	return &authv3.CheckResponse{
		Status: &statuspb.Status{Code: 7}, // PERMISSION_DENIED
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{
					Code: typev3.StatusCode_Forbidden,
				},
				Body: fmt.Sprintf("Access denied: %s", reason),
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "x-ext-authz",
							Value: "denied",
						},
					},
				},
			},
		},
	}, nil
}

// runServer is a testable version of main that accepts dependencies
func runServer(port, configPath string) error {
	cidrs, err := LoadCIDRs(configPath)
	if err != nil {
		return fmt.Errorf("failed to load CIDRs: %v", err)
	}

	server := &ExtAuthServer{cidrs: cidrs}

	// Watch config for changes
	go watchConfig(configPath, func() {
		updated, err := LoadCIDRs(configPath)
		if err != nil {
			log.Printf("Failed to reload CIDRs: %v", err)
			return
		}
		server.cidrs = updated
		log.Printf("Reloaded CIDRs from %s", configPath)
	})

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, server)

	// Health check service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	// Reflection for debugging
	reflection.Register(grpcServer)

	log.Printf("Starting ext-authz server on :%s", port)
	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}
	return nil
}

func main() {
	port := "50051"
	if val := os.Getenv("PORT"); val != "" {
		port = val
	}

	configPath := "/etc/ext-authz/config.yaml"

	if err := runServer(port, configPath); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
