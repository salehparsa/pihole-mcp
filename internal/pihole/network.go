package pihole

import (
	"context"
	"net/url"
)

// Pi-hole returns only 10 devices (and 3 addresses per device) unless asked for more.
const (
	maxDevices   = "1000"
	maxAddresses = "20"
)

// Devices returns the network devices Pi-hole has seen.
func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	return cached(c, "devices", func() ([]Device, error) {
		var out struct {
			Devices []Device `json:"devices"`
		}
		if err := c.get(ctx, "/network/devices", url.Values{"max_devices": {maxDevices}, "max_addresses": {maxAddresses}}, &out); err != nil {
			return nil, err
		}
		return out.Devices, nil
	})
}
