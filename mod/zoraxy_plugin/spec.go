package zoraxy_plugin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const (
	PluginID    = "path-access-control"
	UIPath      = "/ui"
	SniffPath   = "/path-access-sniff"
	CapturePath = "/path-access-capture"
	RouteTag    = "path-access-control"
)

type IntroSpect struct {
	ID                    string        `json:"id"`
	Name                  string        `json:"name"`
	Author                string        `json:"author"`
	AuthorContact         string        `json:"author_contact"`
	Description           string        `json:"description"`
	URL                   string        `json:"url"`
	Type                  int           `json:"type"`
	VersionMajor          int           `json:"version_major"`
	VersionMinor          int           `json:"version_minor"`
	VersionPatch          int           `json:"version_patch"`
	StaticCapturePaths    any           `json:"static_capture_paths"`
	StaticCaptureIngress  string        `json:"static_capture_ingress"`
	DynamicCaptureSniff   string        `json:"dynamic_capture_sniff"`
	DynamicCaptureIngress string        `json:"dynamic_capture_ingress"`
	UIPath                string        `json:"ui_path"`
	SubscriptionPath      string        `json:"subscription_path"`
	SubscriptionsEvents   any           `json:"subscriptions_events"`
	PermittedAPIEndpoints []APIEndpoint `json:"permitted_api_endpoints"`
}

type APIEndpoint struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason"`
}

type ConfigureSpec struct {
	Port       int    `json:"port"`
	APIKey     string `json:"api_key"`
	ZoraxyPort int    `json:"zoraxy_port"`
}

func Spec() IntroSpect {
	return IntroSpect{
		ID:                    PluginID,
		Name:                  "Path Access Control",
		Author:                "IloveeCobrakai",
		AuthorContact:         "https://github.com/IloveeCobrakai",
		Description:           "Apply existing IP/CIDR access rules to individual paths of tagged proxy hosts.",
		URL:                   "https://github.com/IloveeCobrakai/zoraxy-path-access-control",
		Type:                  0,
		VersionMajor:          1,
		VersionMinor:          0,
		VersionPatch:          1,
		DynamicCaptureSniff:   SniffPath,
		DynamicCaptureIngress: CapturePath,
		UIPath:                UIPath,
		PermittedAPIEndpoints: []APIEndpoint{
			{Method: http.MethodGet, Endpoint: "/plugin/api/access/list", Reason: "Loads existing access rules for path checks"},
			{Method: http.MethodPost, Endpoint: "/plugin/api/proxy/list", Reason: "Lists configured HTTP proxy hosts for rule selection"},
			{Method: http.MethodPost, Endpoint: "/plugin/api/proxy/setTags", Reason: "Assigns this router plugin to hosts with path access rules"},
			{Method: http.MethodGet, Endpoint: "/plugin/api/plugins/groups/list", Reason: "Checks the plugin routing group"},
			{Method: http.MethodPost, Endpoint: "/plugin/api/plugins/groups/add", Reason: "Adds this plugin to its routing group"},
		},
	}
}

func ServeAndRecvSpec() (ConfigureSpec, error) {
	if len(os.Args) > 1 && os.Args[1] == "-introspect" {
		if err := json.NewEncoder(os.Stdout).Encode(Spec()); err != nil {
			return ConfigureSpec{}, err
		}
		os.Exit(0)
	}

	for i, arg := range os.Args {
		var raw string
		switch {
		case strings.HasPrefix(arg, "-configure="):
			raw = strings.TrimPrefix(arg, "-configure=")
		case arg == "-configure" && i+1 < len(os.Args):
			raw = os.Args[i+1]
		default:
			continue
		}
		var cfg ConfigureSpec
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return ConfigureSpec{}, err
		}
		if cfg.Port < 1 || cfg.Port > 65535 || cfg.ZoraxyPort < 1 || cfg.ZoraxyPort > 65535 {
			return ConfigureSpec{}, fmt.Errorf("invalid plugin or Zoraxy port")
		}
		if cfg.APIKey == "" {
			return ConfigureSpec{}, fmt.Errorf("missing plugin API key")
		}
		return cfg, nil
	}
	return ConfigureSpec{}, fmt.Errorf("missing -configure argument")
}
