package zoraxy_plugin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxRules = 1000

type PathRule struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	RuleID string `json:"rule_id"`
}

type matchKind uint8

const (
	matchExact matchKind = iota
	matchSubtree
	matchGlob
)

type compiledRule struct {
	rule  PathRule
	kind  matchKind
	value string
}

type ruleSnapshot struct {
	rules   []PathRule
	byHost  map[string][]compiledRule
	loadErr error
}

func (s *Service) loadRules() error {
	data, err := os.ReadFile(s.configFile)
	if os.IsNotExist(err) {
		s.rules.Store(emptyRuleSnapshot())
		return nil
	}
	if err != nil {
		return err
	}
	var rules []PathRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	snapshot, err := compileRules(rules)
	if err != nil {
		return err
	}
	s.rules.Store(snapshot)
	return nil
}

func (s *Service) saveRules(rules []PathRule) error {
	s.rulesUpdateMu.Lock()
	defer s.rulesUpdateMu.Unlock()

	snapshot, err := compileRules(rules)
	if err != nil {
		return err
	}
	if err := s.ensureRoutingFor(snapshot.rules); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snapshot.rules, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.configFile, data, 0600); err != nil {
		return err
	}
	s.rules.Store(snapshot)
	return nil
}

func compileRules(rules []PathRule) (*ruleSnapshot, error) {
	if len(rules) > maxRules {
		return nil, fmt.Errorf("at most %d path rules are allowed", maxRules)
	}
	result := &ruleSnapshot{
		rules:  make([]PathRule, len(rules)),
		byHost: make(map[string][]compiledRule),
	}
	for i := range rules {
		rule := rules[i]
		if err := normalizeRule(&rule); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		result.rules[i] = rule
		compiled := compiledRule{rule: rule, kind: matchExact, value: rule.Path}
		if strings.HasSuffix(rule.Path, "/*") {
			prefix := strings.TrimSuffix(rule.Path, "/*")
			if !strings.ContainsAny(prefix, "*?[\\") {
				compiled.kind, compiled.value = matchSubtree, prefix
			} else {
				compiled.kind = matchGlob
			}
		} else if strings.ContainsAny(rule.Path, "*?[\\") {
			compiled.kind = matchGlob
		}
		result.byHost[rule.Host] = append(result.byHost[rule.Host], compiled)
	}
	return result, nil
}

func emptyRuleSnapshot() *ruleSnapshot {
	return &ruleSnapshot{rules: []PathRule{}, byHost: make(map[string][]compiledRule)}
}

func (s *Service) matchRule(request sniffRequest) (PathRule, bool, error) {
	snapshot := s.rules.Load()
	if snapshot == nil {
		return PathRule{}, false, nil
	}
	if snapshot.loadErr != nil {
		return PathRule{}, false, snapshot.loadErr
	}
	rules := snapshot.byHost[normalizeHost(request.Hostname)]
	if len(rules) == 0 {
		return PathRule{}, false, nil
	}
	requestPath, cleanPath := normalizeRequestPath(request.RequestURI)
	for _, rule := range rules {
		if rule.matches(requestPath) || (cleanPath != requestPath && rule.matches(cleanPath)) {
			return rule.rule, true, nil
		}
	}
	return PathRule{}, false, nil
}

func (r compiledRule) matches(requestPath string) bool {
	switch r.kind {
	case matchExact:
		return requestPath == r.value
	case matchSubtree:
		return requestPath == r.value || strings.HasPrefix(requestPath, r.value+"/")
	default:
		matched, _ := path.Match(r.value, requestPath)
		return matched
	}
}

func normalizeRequestPath(requestURI string) (string, string) {
	if index := strings.IndexByte(requestURI, '?'); index >= 0 {
		requestURI = requestURI[:index]
	}
	if strings.Contains(requestURI, "%") {
		if decoded, err := url.PathUnescape(requestURI); err == nil {
			requestURI = decoded
		}
	}
	if !needsPathClean(requestURI) {
		return requestURI, requestURI
	}
	return requestURI, path.Clean(requestURI)
}

func needsPathClean(requestPath string) bool {
	return strings.Contains(requestPath, "//") ||
		strings.Contains(requestPath, "/./") ||
		strings.Contains(requestPath, "/../") ||
		strings.HasSuffix(requestPath, "/.") ||
		strings.HasSuffix(requestPath, "/..")
}

func normalizeHost(value string) string {
	host := strings.ToLower(strings.TrimSpace(value))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.TrimSuffix(host, ".")
}

func normalizeRule(rule *PathRule) error {
	rule.Host = normalizeHost(rule.Host)
	rule.Path = strings.TrimSpace(rule.Path)
	rule.RuleID = strings.TrimSpace(rule.RuleID)
	if rule.Host == "" || rule.Path == "" || rule.RuleID == "" {
		return fmt.Errorf("host, path and access rule are required")
	}
	if strings.ContainsAny(rule.Host, "/?#") {
		return fmt.Errorf("invalid host %q", rule.Host)
	}
	if len(rule.Path) > 2048 {
		return fmt.Errorf("path pattern is too long")
	}
	if !strings.HasPrefix(rule.Path, "/") || strings.ContainsAny(rule.Path, "?#") {
		return fmt.Errorf("path pattern must start with / and contain no query or fragment")
	}
	if _, err := path.Match(rule.Path, "/"); err != nil {
		return fmt.Errorf("invalid path pattern %q: %w", rule.Path, err)
	}
	return nil
}

func writeFileAtomic(filename string, data []byte, mode os.FileMode) (err error) {
	directory := filepath.Dir(filename)
	tmp, err := os.CreateTemp(directory, ".path-access-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, filename)
}
