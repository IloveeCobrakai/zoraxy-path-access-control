package zoraxy_plugin

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type proxyEndpoint struct {
	Host string   `json:"RootOrMatchingDomain"`
	Tags []string `json:"Tags"`
}

func (s *Service) getProxyHosts() ([]string, error) {
	endpoints, err := s.getProxyEndpoints()
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Host != "" {
			hosts = append(hosts, endpoint.Host)
		}
	}
	sort.Strings(hosts)
	return hosts, nil
}

func (s *Service) getProxyEndpoints() ([]proxyEndpoint, error) {
	response, err := s.postForm("/plugin/api/proxy/list", url.Values{"type": {"host"}})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var endpoints []proxyEndpoint
	if err := decodeLimitedJSON(response, &endpoints); err != nil {
		return nil, err
	}
	return endpoints, nil
}

func (s *Service) ensureRouting() error {
	snapshot := s.rules.Load()
	if snapshot == nil || snapshot.loadErr != nil {
		return nil
	}
	return s.ensureRoutingFor(snapshot.rules)
}

func (s *Service) ensureRoutingFor(rules []PathRule) error {
	if len(rules) == 0 {
		return nil
	}
	if err := s.ensurePluginGroup(); err != nil {
		return err
	}
	endpoints, err := s.getProxyEndpoints()
	if err != nil {
		return err
	}
	configured := make(map[string]proxyEndpoint, len(endpoints))
	for _, endpoint := range endpoints {
		configured[normalizeHost(endpoint.Host)] = endpoint
	}
	targetHosts := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		targetHosts[rule.Host] = struct{}{}
	}
	for host := range targetHosts {
		endpoint, ok := configured[host]
		if !ok {
			return fmt.Errorf("configured HTTP proxy host %q no longer exists", host)
		}
		if stringInSlice(RouteTag, endpoint.Tags) {
			continue
		}
		tags := append(append([]string{}, endpoint.Tags...), RouteTag)
		response, err := s.postForm("/plugin/api/proxy/setTags", url.Values{
			"rootname": {endpoint.Host},
			"tags":     {strings.Join(tags, ",")},
		})
		if err != nil {
			return fmt.Errorf("assign routing tag to %q: %w", endpoint.Host, err)
		}
		drainAndClose(response.Body)
	}
	return nil
}

func (s *Service) ensurePluginGroup() error {
	groups := make(map[string][]string)
	if err := s.getJSON("/plugin/api/plugins/groups/list", &groups); err != nil {
		return err
	}
	if stringInSlice(PluginID, groups[RouteTag]) {
		return nil
	}
	response, err := s.postForm("/plugin/api/plugins/groups/add", url.Values{
		"tag":       {RouteTag},
		"plugin_id": {PluginID},
	})
	if err != nil {
		return err
	}
	drainAndClose(response.Body)
	return nil
}

func (s *Service) getJSON(endpoint string, target any) error {
	request, err := s.newRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("plugin API %s returned %s", endpoint, response.Status)
	}
	return decodeLimitedJSON(response, target)
}

func (s *Service) postForm(endpoint string, form url.Values) (*http.Response, error) {
	request, err := s.newRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		drainAndClose(response.Body)
		return nil, fmt.Errorf("plugin API %s returned %s", endpoint, response.Status)
	}
	return response, nil
}

func (s *Service) newRequest(method, endpoint string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", s.cfg.ZoraxyPort, endpoint), body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+s.cfg.APIKey)
	return request, nil
}

func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4<<10))
	_ = body.Close()
}

func stringInSlice(needle string, values []string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
