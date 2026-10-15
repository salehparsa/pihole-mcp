// Package instances maps configured instance names to Pi-hole clients.
package instances

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/salehparsa/pihole-mcp/internal/config"
	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

// Registry holds one client per configured Pi-hole. The first is the default.
type Registry struct {
	order   []string
	clients map[string]*pihole.Client
}

// New builds clients for every configured instance.
func New(cfgs []config.Instance) (*Registry, error) {
	r := &Registry{clients: map[string]*pihole.Client{}}
	for _, in := range cfgs {
		c, err := pihole.New(pihole.Options{BaseURL: in.URL, Password: in.Password, Timeout: in.Timeout, TLSSkipVerify: in.TLSSkipVerify})
		if err != nil {
			return nil, fmt.Errorf("instance %q: %w", in.Name, err)
		}
		r.order = append(r.order, in.Name)
		r.clients[in.Name] = c
	}
	return r, nil
}

// FromClients builds a registry from ready clients (tests).
func FromClients(m map[string]*pihole.Client, order ...string) *Registry {
	return &Registry{order: order, clients: m}
}

// Get returns the named instance, or the default when name is empty.
func (r *Registry) Get(name string) (string, *pihole.Client, error) {
	if name == "" {
		if len(r.order) == 0 {
			return "", nil, fmt.Errorf("no Pi-hole instances configured")
		}
		name = r.order[0]
	}
	c, ok := r.clients[name]
	if !ok {
		names := append([]string(nil), r.order...)
		sort.Strings(names)
		return "", nil, fmt.Errorf("unknown instance %q (configured: %s)", name, strings.Join(names, ", "))
	}
	return name, c, nil
}

// Names lists instance names, default first.
func (r *Registry) Names() []string { return append([]string(nil), r.order...) }

// Close logs out of every instance.
func (r *Registry) Close(ctx context.Context) {
	for _, c := range r.clients {
		_ = c.Close(ctx)
	}
}
