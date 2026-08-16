package zoraxy_plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

type AccessRule struct {
	ID                             string             `json:"ID"`
	Name                           string             `json:"Name"`
	Desc                           string             `json:"Desc"`
	BlacklistEnabled               bool               `json:"BlacklistEnabled"`
	WhitelistEnabled               bool               `json:"WhitelistEnabled"`
	WhitelistAllowLocalAndLoopback bool               `json:"WhitelistAllowLocalAndLoopback"`
	TrustProxyHeadersOnly          bool               `json:"TrustProxyHeadersOnly"`
	WhiteListCountryCode           *map[string]string `json:"WhiteListCountryCode"`
	WhiteListIP                    *map[string]string `json:"WhiteListIP"`
	BlackListContryCode            *map[string]string `json:"BlackListContryCode"`
	BlackListIP                    *map[string]string `json:"BlackListIP"`
}

type compiledAccessRule struct {
	rule      AccessRule
	whitelist ipMatcher
	blacklist ipMatcher
}

type accessSnapshot struct {
	rules       map[string]compiledAccessRule
	fetchedAt   time.Time
	lastAttempt time.Time
	lastErr     error
}

type ipMatcher struct {
	exact     map[netip.Addr]struct{}
	prefixes  []netip.Prefix
	wildcards [][4]int16
}

func (s *Service) accessRulesForRequest() (map[string]compiledAccessRule, error) {
	snapshot := s.access.Load()
	if snapshot == nil || snapshot.rules == nil || time.Since(snapshot.fetchedAt) > accessMaxAge {
		_ = s.refreshAccessRules(false)
		snapshot = s.access.Load()
	}
	if snapshot == nil || snapshot.rules == nil {
		return nil, fmt.Errorf("access-rule data is unavailable")
	}
	if time.Since(snapshot.fetchedAt) > accessMaxAge {
		return nil, fmt.Errorf("access-rule data is stale")
	}
	return snapshot.rules, nil
}

func (s *Service) accessRulesForUI() ([]AccessRule, error) {
	rules, err := s.accessRulesForRequest()
	if err != nil {
		return nil, err
	}
	result := make([]AccessRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.rule)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result, nil
}

func (s *Service) refreshAccessRules(force bool) error {
	s.accessRefreshMu.Lock()
	defer s.accessRefreshMu.Unlock()

	current := s.access.Load()
	now := time.Now()
	if !force && current != nil && now.Sub(current.lastAttempt) < accessRetryDelay {
		return current.lastErr
	}

	var list []AccessRule
	if err := s.getJSON("/plugin/api/access/list", &list); err != nil {
		next := &accessSnapshot{lastAttempt: now, lastErr: err}
		if current != nil {
			next.rules, next.fetchedAt = current.rules, current.fetchedAt
		}
		s.access.Store(next)
		return err
	}

	rules := make(map[string]compiledAccessRule, len(list))
	for _, rule := range list {
		rules[rule.ID] = compiledAccessRule{
			rule:      rule,
			whitelist: compileIPMatcher(rule.WhiteListIP),
			blacklist: compileIPMatcher(rule.BlackListIP),
		}
	}
	s.access.Store(&accessSnapshot{rules: rules, fetchedAt: now, lastAttempt: now})
	return nil
}

func evaluateAccess(rule compiledAccessRule, remoteAddr string) (bool, string) {
	if (rule.rule.BlacklistEnabled && hasEntries(rule.rule.BlackListContryCode)) ||
		(rule.rule.WhitelistEnabled && hasEntries(rule.rule.WhiteListCountryCode)) {
		return true, "Country-based access rules are not supported by this plugin."
	}
	ip, ok := requesterIP(remoteAddr)
	if !ok {
		return true, "The client IP address is invalid."
	}
	if rule.rule.BlacklistEnabled && rule.blacklist.matches(ip) {
		return true, "Forbidden"
	}
	if !rule.rule.WhitelistEnabled {
		return false, ""
	}
	if rule.rule.WhitelistAllowLocalAndLoopback && (ip.IsLoopback() || ip.IsPrivate()) {
		return false, ""
	}
	if !rule.whitelist.matches(ip) {
		return true, "Forbidden"
	}
	return false, ""
}

func requesterIP(remote string) (netip.Addr, bool) {
	if address, err := netip.ParseAddrPort(remote); err == nil {
		return address.Addr().Unmap(), true
	}
	address, err := netip.ParseAddr(strings.Trim(remote, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func compileIPMatcher(entries *map[string]string) ipMatcher {
	matcher := ipMatcher{exact: make(map[netip.Addr]struct{})}
	if entries == nil {
		return matcher
	}
	for value := range *entries {
		value = strings.TrimSpace(value)
		if address, err := netip.ParseAddr(value); err == nil {
			matcher.exact[address.Unmap()] = struct{}{}
			continue
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			matcher.prefixes = append(matcher.prefixes, prefix)
			continue
		}
		if wildcard, ok := parseIPv4Wildcard(value); ok {
			matcher.wildcards = append(matcher.wildcards, wildcard)
		}
	}
	return matcher
}

func (m ipMatcher) matches(address netip.Addr) bool {
	if _, ok := m.exact[address]; ok {
		return true
	}
	for _, prefix := range m.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	if address.Is4() {
		octets := address.As4()
		for _, wildcard := range m.wildcards {
			matched := true
			for i := range wildcard {
				if wildcard[i] >= 0 && byte(wildcard[i]) != octets[i] {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
	}
	return false
}

func parseIPv4Wildcard(value string) ([4]int16, bool) {
	var result [4]int16
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return result, false
	}
	for i, part := range parts {
		if part == "*" {
			result[i] = -1
			continue
		}
		number, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return result, false
		}
		result[i] = int16(number)
	}
	return result, true
}

func hasEntries(entries *map[string]string) bool {
	return entries != nil && len(*entries) > 0
}

func decodeLimitedJSON(response *http.Response, target any) error {
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxBodySize+1))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}
