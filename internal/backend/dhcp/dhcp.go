package dhcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// perTry is the wait budget for a single DISCOVER/REQUEST exchange before we retry.
const perTry = 4 * time.Second

// maxTries bounds the DISCOVER->ACK attempts within a single Acquire (ctx still wins).
const maxTries = 5

// leaseState is the minimal per-interface memory kept so Release can unicast a matching
// DHCPRELEASE to the server that granted the lease.
type leaseState struct {
	mac      net.HardwareAddr
	clientIP net.IP
	serverID net.IP
}

// Client is the DHCPv4 client. It holds only the last lease per interface, enough to
// release it later; it is safe for concurrent use across interfaces.
type Client struct {
	mu     sync.Mutex
	leases map[string]leaseState
}

// New returns a ready DHCPv4 client.
func New() *Client {
	return &Client{leases: make(map[string]leaseState)}
}

// Acquire runs a full DHCPv4 handshake on ifname using mac as the client hardware address
// and returns the resulting lease. It broadcasts from 0.0.0.0:68 and asks the server to
// reply by broadcast (the BROADCAST flag), so it works with no address configured. It
// retries with backoff until a lease is bound or ctx is cancelled.
func (c *Client) Acquire(ctx context.Context, ifname string, mac net.HardwareAddr) (*core.Lease, error) {
	if len(mac) != 6 {
		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			return nil, fmt.Errorf("dhcp: resolve %s: %w", ifname, err)
		}
		mac = iface.HardwareAddr
		if len(mac) != 6 {
			return nil, fmt.Errorf("dhcp: %s has no usable MAC", ifname)
		}
	}
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("dhcp: resolve %s: %w", ifname, err)
	}

	sock, err := openRawSock(iface.Index)
	if err != nil {
		return nil, fmt.Errorf("dhcp: open socket on %s: %w", ifname, err)
	}
	defer sock.close()

	var lastErr error
	for try := 0; try < maxTries; try++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lease, err := c.handshake(ctx, sock, mac)
		if err == nil {
			c.mu.Lock()
			c.leases[ifname] = leaseState{mac: mac, clientIP: lease.IP, serverID: lease.ServerID}
			c.mu.Unlock()
			return lease, nil
		}
		lastErr = err
		// linear backoff between full attempts, still yielding to ctx.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(try+1) * time.Second):
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no lease")
	}
	return nil, fmt.Errorf("dhcp: %s: %w", ifname, lastErr)
}

// handshake performs one DISCOVER/OFFER/REQUEST/ACK round with a fresh xid.
func (c *Client) handshake(ctx context.Context, sock *rawSock, mac net.HardwareAddr) (*core.Lease, error) {
	xid, err := newXID()
	if err != nil {
		return nil, err
	}

	discover := buildMsg(msgDiscover, xid, mac, nil, nil)
	if err := sock.send(discover); err != nil {
		return nil, err
	}
	offer, err := sock.recvReply(ctx, xid, msgOffer, perTry)
	if err != nil {
		return nil, err
	}
	offeredIP := offer.yiaddr
	serverID := offer.opt4(optServerID)
	if offeredIP == nil || serverID == nil {
		return nil, errors.New("offer missing address or server id")
	}

	request := buildMsg(msgRequest, xid, mac, offeredIP, serverID)
	if err := sock.send(request); err != nil {
		return nil, err
	}
	ack, err := sock.recvReply(ctx, xid, msgAck, perTry)
	if err != nil {
		return nil, err
	}
	return ack.toLease()
}

// Release sends a DHCPRELEASE for the last lease tracked on ifname, unicast to the server
// that granted it. It is a best-effort no-op when no lease is tracked.
func (c *Client) Release(ifname string) error {
	c.mu.Lock()
	st, ok := c.leases[ifname]
	if ok {
		delete(c.leases, ifname)
	}
	c.mu.Unlock()
	if !ok || st.clientIP == nil || st.serverID == nil {
		return nil
	}
	return sendRelease(st)
}
