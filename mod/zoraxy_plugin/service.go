package zoraxy_plugin

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxBodySize       = 1 << 20
	accessRefreshRate = 20 * time.Second
	accessMaxAge      = 60 * time.Second
	accessRetryDelay  = 5 * time.Second
)

type Assets struct {
	IndexHTML     []byte
	ForbiddenHTML []byte
}

type Service struct {
	cfg        ConfigureSpec
	assets     Assets
	configFile string
	client     *http.Client
	mux        *http.ServeMux

	rules         atomic.Pointer[ruleSnapshot]
	rulesUpdateMu sync.Mutex

	access          atomic.Pointer[accessSnapshot]
	accessRefreshMu sync.Mutex

	captures *captureStore
}

func NewService(cfg ConfigureSpec, assets Assets, configFile string) *Service {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
	}
	s := &Service{
		cfg:        cfg,
		assets:     assets,
		configFile: configFile,
		client:     &http.Client{Transport: transport, Timeout: 5 * time.Second},
		mux:        http.NewServeMux(),
		captures:   newCaptureStore(),
	}
	if err := s.loadRules(); err != nil {
		s.rules.Store(&ruleSnapshot{loadErr: err})
		log.Printf("unable to load path rules: %v", err)
	}
	s.registerRoutes()
	return s
}

func (s *Service) Handler() http.Handler { return s.mux }

func (s *Service) Start(ctx context.Context) {
	if err := s.refreshAccessRules(true); err != nil {
		log.Printf("unable to load access rules: %v", err)
	}
	if err := s.ensureRouting(); err != nil {
		log.Printf("unable to configure path-access routing: %v", err)
	}
	go s.refreshLoop(ctx)
}

func (s *Service) Close() {
	if transport, ok := s.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (s *Service) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(accessRefreshRate)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.refreshAccessRules(true); err != nil {
				log.Printf("unable to refresh access rules: %v", err)
			}
		}
	}
}
