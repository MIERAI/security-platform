package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Device is one discovered asset, in the shape of adapters/discovery.py.
type Device struct {
	Name    string         `json:"name"`
	Address *string        `json:"address"`
	OS      string         `json:"os"`
	Online  bool           `json:"online"`
	Attrs   map[string]any `json:"attrs"`
}

// instance is a VM as both listing APIs describe it.
type instance struct {
	name, zone, status string
	internal, external []string
}

// DiscoverGCP lists the Compute Engine VM instances of one or more projects, READ-ONLY (`discovery: gcp`):
// {project_id, project_ids?, api?: cloudasset|compute, address?: external|internal, include_stopped?,
// max_hosts?: 1024, refuse_over_privileged?: true, + the keys of a GCP cloud account}. It authenticates exactly like
// a GCP account and refuses an over-privileged identity. Stopped instances are left out unless include_stopped.
func DiscoverGCP(ctx context.Context, cfg Account, deps Deps) ([]Device, error) {
	acct := Account{}
	for k, v := range cfg {
		acct[k] = v
	}
	acct["provider"] = "gcp"
	p, err := newGCP(acct, deps)
	if err != nil {
		return nil, err
	}
	if rerr := refuseOverPrivileged(ctx, p, cfg); rerr != nil {
		return nil, rerr
	}
	lister, err := discoveryLister(cfg)
	if err != nil {
		return nil, err
	}
	want := cfg.StrOr("address", "external")
	if want != "external" && want != "internal" {
		return nil, fmt.Errorf("gcp discovery address '%s' unknown (external, internal)", want)
	}
	tok, err := p.token(ctx)
	if err != nil {
		return nil, err
	}
	client := p.bearerClient(ctx, tok)
	limit := cfg.Int("max_hosts", 1024)
	projects := cfg.List("project_ids")
	if len(projects) == 0 {
		projects = []string{p.account}
	}
	var out []Device
	for _, project := range projects {
		insts, err := lister(ctx, client, project, limit)
		if err != nil {
			return nil, err
		}
		out = append(out, devices(project, insts, want, cfg.Bool("include_stopped", false))...)
	}
	return out, nil
}

func refuseOverPrivileged(ctx context.Context, p *gcpProvider, cfg Account) error {
	if !cfg.Bool("refuse_over_privileged", true) {
		return nil
	}
	perm, err := p.Permissions(ctx)
	if err != nil {
		return err
	}
	if len(perm.WriteCapable) > 0 {
		return failf("refused: the discovery identity is over-privileged (read-only expected): %s",
			trunc(strings.Join(perm.WriteCapable, ", "), 200))
	}
	return nil
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

type listerFunc func(ctx context.Context, client *http.Client, project string, limit int) ([]instance, error)

func discoveryLister(cfg Account) (listerFunc, error) {
	switch api := cfg.StrOr("api", "cloudasset"); api {
	case "cloudasset":
		base := strings.TrimRight(cfg.StrOr("cloudasset_url", "https://cloudasset.googleapis.com/v1"), "/")
		return func(ctx context.Context, c *http.Client, project string, limit int) ([]instance, error) {
			return listAssets(ctx, c, base, project, limit)
		}, nil
	case "compute":
		base := strings.TrimRight(cfg.StrOr("compute_url", "https://compute.googleapis.com/compute/v1"), "/")
		return func(ctx context.Context, c *http.Client, project string, limit int) ([]instance, error) {
			return listCompute(ctx, c, base, project, limit)
		}, nil
	default:
		return nil, fmt.Errorf("gcp discovery api '%s' unknown (cloudasset, compute)", api)
	}
}

func devices(project string, insts []instance, want string, includeStopped bool) []Device {
	var out []Device
	for _, i := range insts {
		running := i.status == "RUNNING"
		if !running && !includeStopped {
			continue
		}
		addrs := i.external
		if want == "internal" {
			addrs = i.internal
		}
		d := Device{Name: i.name, Online: running, Attrs: map[string]any{"provider": "gcp", "project": project,
			"zone": i.zone, "status": i.status, "online_verified": running, "external": len(i.external) > 0,
			"asset": "cloud:gcp/" + project + "/compute/" + i.name}}
		if len(addrs) > 0 {
			a := addrs[0]
			d.Address = &a
		}
		out = append(out, d)
	}
	return out
}

// listAssets: Cloud Asset API searchAllResources (asset type compute Instance), page by page.
func listAssets(ctx context.Context, client *http.Client, base, project string, limit int) ([]instance, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*callTimeout)
	defer cancel()
	var out []instance
	for page := ""; ; {
		q := url.Values{"assetTypes": {"compute.googleapis.com/Instance"}, "pageSize": {"500"}}
		if page != "" {
			q.Set("pageToken", page)
		}
		var resp struct {
			Results       []assetResult `json:"results"`
			NextPageToken string        `json:"nextPageToken"`
		}
		endpoint := base + "/projects/" + url.PathEscape(project) + ":searchAllResources?" + q.Encode()
		if err := googleJSON(ctx, client, apiRequest{http.MethodGet, endpoint, nil}, &resp); err != nil {
			return nil, failf("gcp discovery searchAllResources: %s", googleReason(err, base))
		}
		for _, r := range resp.Results {
			out = append(out, r.instance())
		}
		if len(out) > limit {
			return nil, fmt.Errorf("gcp project %s has more than %d instances (max_hosts)", project, limit)
		}
		if page = resp.NextPageToken; page == "" {
			return out, nil
		}
	}
}

// assetResult is one ResourceSearchResult of the Cloud Asset API.
type assetResult struct {
	Name, DisplayName, Location, State string
	AdditionalAttributes               struct {
		InternalIPs []string `json:"internalIPs"`
		ExternalIPs []string `json:"externalIPs"`
	} `json:"additionalAttributes"`
}

func (r *assetResult) instance() instance {
	name := r.DisplayName
	if name == "" {
		name = r.Name[strings.LastIndex(r.Name, "/")+1:]
	}
	return instance{name: name, zone: r.Location, status: r.State, internal: r.AdditionalAttributes.InternalIPs,
		external: r.AdditionalAttributes.ExternalIPs}
}

// listCompute: Compute Engine aggregated instances.list, page by page.
func listCompute(ctx context.Context, client *http.Client, base, project string, limit int) ([]instance, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*callTimeout)
	defer cancel()
	var out []instance
	for page := ""; ; {
		q := url.Values{"maxResults": {"500"}, "returnPartialSuccess": {"true"}}
		if page != "" {
			q.Set("pageToken", page)
		}
		var resp struct {
			Items         map[string]struct{ Instances []computeVM } `json:"items"`
			NextPageToken string                                     `json:"nextPageToken"`
		}
		endpoint := base + "/projects/" + url.PathEscape(project) + "/aggregated/instances?" + q.Encode()
		if err := googleJSON(ctx, client, apiRequest{http.MethodGet, endpoint, nil}, &resp); err != nil {
			return nil, failf("gcp discovery instances: %s", googleReason(err, base))
		}
		out = append(out, aggregatedInstances(resp.Items)...)
		if len(out) > limit {
			return nil, fmt.Errorf("gcp project %s has more than %d instances (max_hosts)", project, limit)
		}
		if page = resp.NextPageToken; page == "" {
			return out, nil
		}
	}
}

// aggregatedInstances flattens an aggregated list's scopes ("zones/<zone>"), in scope order.
func aggregatedInstances(items map[string]struct{ Instances []computeVM }) []instance {
	scopes := make([]string, 0, len(items))
	for s := range items {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	var out []instance
	for _, s := range scopes {
		for i := range items[s].Instances {
			out = append(out, items[s].Instances[i].instance(strings.TrimPrefix(s, "zones/")))
		}
	}
	return out
}

// computeVM is the part of a Compute Engine Instance discovery reads.
type computeVM struct {
	Name, Status      string
	NetworkInterfaces []struct {
		NetworkIP     string `json:"networkIP"`
		AccessConfigs []struct {
			NatIP string `json:"natIP"`
		} `json:"accessConfigs"`
	} `json:"networkInterfaces"`
}

func (vm *computeVM) instance(zone string) instance {
	inst := instance{name: vm.Name, zone: zone, status: vm.Status}
	for _, n := range vm.NetworkInterfaces {
		if n.NetworkIP != "" {
			inst.internal = append(inst.internal, n.NetworkIP)
		}
		for _, ac := range n.AccessConfigs {
			if ac.NatIP != "" {
				inst.external = append(inst.external, ac.NatIP)
			}
		}
	}
	return inst
}
