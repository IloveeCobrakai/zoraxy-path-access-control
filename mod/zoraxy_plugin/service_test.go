package zoraxy_plugin

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func ruleMap(entries map[string]string) *map[string]string { return &entries }

func newTestService(t *testing.T) *Service {
	t.Helper()
	service := NewService(ConfigureSpec{}, Assets{
		IndexHTML:     []byte(`<meta name="zoraxy.csrf.Token" content="{{.csrfToken}}"><button onclick="addRule()">Add</button>`),
		ForbiddenHTML: []byte(`<!-- Zoraxy Forbidden Template -->Forbidden`),
	}, filepath.Join(t.TempDir(), "rules.json"))
	return service
}

func TestEvaluateAccess(t *testing.T) {
	tests := []struct {
		name    string
		rule    AccessRule
		ip      string
		blocked bool
	}{
		{"blacklisted CIDR", AccessRule{BlacklistEnabled: true, BlackListIP: ruleMap(map[string]string{"203.0.113.0/24": "test"})}, "203.0.113.42", true},
		{"whitelisted CIDR", AccessRule{WhitelistEnabled: true, WhiteListIP: ruleMap(map[string]string{"192.168.0.0/16": "LAN"})}, "192.168.1.10", false},
		{"non-whitelisted address", AccessRule{WhitelistEnabled: true, WhiteListIP: ruleMap(map[string]string{"192.168.0.0/16": "LAN"})}, "198.51.100.10", true},
		{"IPv4 wildcard", AccessRule{BlacklistEnabled: true, BlackListIP: ruleMap(map[string]string{"203.0.*.*": "test"})}, "203.0.113.42", true},
		{"country rule fails closed", AccessRule{BlacklistEnabled: true, BlackListContryCode: ruleMap(map[string]string{"DE": "example"})}, "198.51.100.10", true},
		{"invalid client IP fails closed", AccessRule{}, "invalid", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compiled := compiledAccessRule{
				rule:      test.rule,
				whitelist: compileIPMatcher(test.rule.WhiteListIP),
				blacklist: compileIPMatcher(test.rule.BlackListIP),
			}
			blocked, _ := evaluateAccess(compiled, test.ip)
			if blocked != test.blocked {
				t.Fatalf("blocked = %v, want %v", blocked, test.blocked)
			}
		})
	}
}

func TestMatchRuleUsesIndexedHostAndNormalizedPath(t *testing.T) {
	service := newTestService(t)
	snapshot, err := compileRules([]PathRule{{Host: "vault.example.com", Path: "/admin/*", RuleID: "lan"}})
	if err != nil {
		t.Fatal(err)
	}
	service.rules.Store(snapshot)
	tests := []struct {
		host, uri string
		matched   bool
	}{
		{"vault.example.com:443", "/admin/settings?tab=users", true},
		{"vault.example.com", "/admin", true},
		{"VAULT.EXAMPLE.COM.:443", "/public/../admin/settings", true},
		{"vault.example.com", "/", false},
		{"other.example.com", "/admin/settings", false},
	}
	for _, test := range tests {
		_, matched, err := service.matchRule(sniffRequest{Hostname: test.host, RequestURI: test.uri})
		if err != nil || matched != test.matched {
			t.Fatalf("match(%q, %q) = %v, %v", test.host, test.uri, matched, err)
		}
	}
}

func TestGetProxyHosts(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable: %v", err)
	}
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/plugin/api/proxy/list" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer api-key" {
			t.Fatal("missing API authorization")
		}
		_, _ = w.Write([]byte(`[{"RootOrMatchingDomain":"z.example"},{"RootOrMatchingDomain":"a.example"}]`))
	}))
	api.Listener = listener
	api.Start()
	defer api.Close()
	port, _ := strconv.Atoi(strings.TrimPrefix(api.URL, "http://127.0.0.1:"))
	service := NewService(ConfigureSpec{ZoraxyPort: port, APIKey: "api-key"}, Assets{}, filepath.Join(t.TempDir(), "rules.json"))
	hosts, err := service.getProxyHosts()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(hosts, ","); got != "a.example,z.example" {
		t.Fatalf("hosts = %q", got)
	}
}

func TestUIEscapesCSRFToken(t *testing.T) {
	service := newTestService(t)
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.Header.Set("X-Zoraxy-Csrf", `"><script>alert(1)</script>`)
	resp := httptest.NewRecorder()
	service.handleUI(resp, req)
	if strings.Contains(resp.Body.String(), `<script>alert(1)</script>`) {
		t.Fatal("CSRF token was not escaped")
	}
}

func TestSaveRulesRejectsInvalidPath(t *testing.T) {
	service := newTestService(t)
	err := service.saveRules([]PathRule{{Host: "example.com", Path: "admin/*", RuleID: "lan"}})
	if err == nil || !strings.Contains(err.Error(), "must start with /") {
		t.Fatalf("error = %v, want invalid path error", err)
	}
}

func TestBlockedCaptureUsesForbiddenPage(t *testing.T) {
	service := newTestService(t)
	service.captures.put("request-id", http.StatusForbidden, "blocked")
	req := httptest.NewRequest(http.MethodGet, "/path-access-capture/", nil)
	req.Header.Set("X-Zoraxy-RequestID", "request-id")
	resp := httptest.NewRecorder()
	service.handleCapture(resp, req)
	if resp.Code != http.StatusForbidden || !strings.Contains(resp.Body.String(), "Zoraxy Forbidden Template") {
		t.Fatalf("unexpected forbidden response: %d %q", resp.Code, resp.Body.String())
	}
}

func TestConfigurationLoadErrorFailsClosed(t *testing.T) {
	config := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(config, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	service := NewService(ConfigureSpec{}, Assets{}, config)
	req := httptest.NewRequest(http.MethodPost, SniffPath+"/", strings.NewReader(`{"hostname":"example.com","request_uri":"/"}`))
	req.Header.Set("X-Zoraxy-RequestID", "request-id")
	resp := httptest.NewRecorder()
	service.handleSniff(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("sniff status = %d, want 200", resp.Code)
	}
	if result, ok := service.captures.take("request-id"); !ok || result.status != http.StatusServiceUnavailable {
		t.Fatalf("capture = %#v, %v; want 503", result, ok)
	}
}

func TestConcurrentHotPath(t *testing.T) {
	service := newTestService(t)
	snapshot, _ := compileRules([]PathRule{{Host: "example.com", Path: "/admin/*", RuleID: "lan"}})
	service.rules.Store(snapshot)
	service.access.Store(&accessSnapshot{
		rules:     map[string]compiledAccessRule{"lan": {rule: AccessRule{ID: "lan"}}},
		fetchedAt: time.Now(), lastAttempt: time.Now(),
	})
	var wait sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for request := 0; request < 100; request++ {
				matched, ok, err := service.matchRule(sniffRequest{Hostname: "example.com", RequestURI: "/admin/users"})
				if err != nil || !ok || matched.RuleID != "lan" {
					t.Errorf("unexpected match result: %#v, %v, %v", matched, ok, err)
					return
				}
			}
		}(worker)
	}
	wait.Wait()
}

func TestCaptureStoreRemainsBoundedUnderConcurrency(t *testing.T) {
	store := newCaptureStore()
	var wait sync.WaitGroup
	for worker := 0; worker < 64; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for request := 0; request < 200; request++ {
				store.put(strconv.Itoa(worker)+"-"+strconv.Itoa(request), http.StatusForbidden, "blocked")
			}
		}(worker)
	}
	wait.Wait()
	total := 0
	for i := range store.shards {
		shard := &store.shards[i]
		shard.mu.Lock()
		total += len(shard.entries)
		shard.mu.Unlock()
	}
	if total > captureShardCount*capturesPerShard {
		t.Fatalf("capture store contains %d entries, want at most %d", total, captureShardCount*capturesPerShard)
	}
}

func TestSpecMatchesRepositoryMetadata(t *testing.T) {
	spec := Spec()
	if spec.ID != PluginID || spec.URL != "https://github.com/IloveeCobrakai/zoraxy-path-access-control" {
		t.Fatalf("unexpected plugin metadata: %#v", spec)
	}
}

func BenchmarkMatchRule(b *testing.B) {
	service := NewService(ConfigureSpec{}, Assets{}, filepath.Join(b.TempDir(), "rules.json"))
	rules := make([]PathRule, 1000)
	for i := range rules {
		rules[i] = PathRule{Host: "host-" + strconv.Itoa(i%100) + ".example.com", Path: "/admin/*", RuleID: "lan"}
	}
	snapshot, _ := compileRules(rules)
	service.rules.Store(snapshot)
	request := sniffRequest{Hostname: "host-42.example.com", RequestURI: "/admin/users?id=1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = service.matchRule(request)
	}
}
