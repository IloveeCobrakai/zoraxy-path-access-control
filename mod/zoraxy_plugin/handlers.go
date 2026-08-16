package zoraxy_plugin

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
)

type sniffRequest struct {
	Hostname   string `json:"hostname"`
	RequestURI string `json:"request_uri"`
	RemoteAddr string `json:"remote_addr"`
}

func (s *Service) registerRoutes() {
	s.mux.HandleFunc(UIPath+"/", s.handleUI)
	s.mux.HandleFunc(UIPath+"/api/rules", s.handleRules)
	s.mux.HandleFunc(SniffPath+"/", s.handleSniff)
	s.mux.HandleFunc(CapturePath+"/", s.handleCapture)
}

func (s *Service) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != UIPath+"/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	page := strings.ReplaceAll(string(s.assets.IndexHTML), "{{.csrfToken}}", html.EscapeString(r.Header.Get("X-Zoraxy-Csrf")))
	_, _ = w.Write([]byte(page))
}

func (s *Service) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snapshot := s.rules.Load()
		if snapshot == nil {
			snapshot = emptyRuleSnapshot()
		}
		access, err := s.accessRulesForUI()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hosts, err := s.getProxyHosts()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			Rules  []PathRule   `json:"rules"`
			Access []AccessRule `json:"access"`
			Hosts  []string     `json:"hosts"`
		}{snapshot.rules, access, hosts})
	case http.MethodPut:
		defer r.Body.Close()
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize))
		decoder.DisallowUnknownFields()
		var rules []PathRule
		if err := decoder.Decode(&rules); err != nil {
			http.Error(w, "invalid rules: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := ensureJSONEOF(decoder); err != nil {
			http.Error(w, "invalid rules: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.saveRules(rules); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Service) handleSniff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var request sniffRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&request); err != nil {
		http.Error(w, "invalid sniff payload", http.StatusBadRequest)
		return
	}
	rule, matched, err := s.matchRule(request)
	if err != nil {
		s.capture(w, r, http.StatusServiceUnavailable, "Path-access configuration is invalid.")
		return
	}
	if !matched {
		http.Error(w, "skip", http.StatusNotImplemented)
		return
	}
	access, err := s.accessRulesForRequest()
	if err != nil {
		s.capture(w, r, http.StatusServiceUnavailable, "Access-rule data is currently unavailable.")
		return
	}
	accessRule, ok := access[rule.RuleID]
	if !ok {
		s.capture(w, r, http.StatusServiceUnavailable, "The configured access rule no longer exists.")
		return
	}
	blocked, reason := evaluateAccess(accessRule, request.RemoteAddr)
	if !blocked {
		http.Error(w, "skip", http.StatusNotImplemented)
		return
	}
	s.capture(w, r, http.StatusForbidden, reason)
}

func (s *Service) capture(w http.ResponseWriter, r *http.Request, status int, message string) {
	_ = s.captures.put(r.Header.Get("X-Zoraxy-RequestID"), status, message)
	w.WriteHeader(http.StatusOK)
}

func (s *Service) handleCapture(w http.ResponseWriter, r *http.Request) {
	result, ok := s.captures.take(r.Header.Get("X-Zoraxy-RequestID"))
	if !ok {
		http.Error(w, "Path access request expired.", http.StatusServiceUnavailable)
		return
	}
	if result.status == http.StatusForbidden {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(s.assets.ForbiddenHTML)
		return
	}
	http.Error(w, result.message, result.status)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
