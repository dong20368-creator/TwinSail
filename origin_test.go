package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

func TestOriginAddressFallback(t *testing.T) {
	for _, tc := range []struct {
		budget, firstAttempt time.Duration
	}{{8 * time.Second, 2 * time.Second}, {3 * time.Second, 1500 * time.Millisecond}} {
		t.Run(tc.budget.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
				defer cancel()
				var ips []netip.Addr
				for _, addr := range []string{"127.0.0.1", "0.2.3.4", "10.0.0.1", "100.64.0.1", "169.254.1.2", "::1", "2606:4700::1", "::ffff:1.1.1.1", "224.0.0.1", "8.8.8.8"} {
					ips = append(ips, netip.MustParseAddr(addr))
				}
				var calls []string
				started := time.Now()
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				conn, err := dialPublicIPs(ctx, ips, "443", func(attempt context.Context, network, address string) (net.Conn, error) {
					calls = append(calls, network+" "+address)
					if len(calls) == 1 {
						<-attempt.Done()
						return nil, attempt.Err()
					}
					deadline, ok := attempt.Deadline()
					end, _ := ctx.Deadline()
					if !ok || !deadline.Equal(end) || attempt.Err() != nil {
						t.Fatal("last address did not receive remaining parent budget")
					}
					return a, nil
				})
				if err != nil || conn != a || time.Since(started) != tc.firstAttempt {
					t.Fatalf("fallback after %v: returned expected connection = %v, err = %v", time.Since(started), conn == a, err)
				}
				if want := []string{"tcp4 1.1.1.1:443", "tcp4 8.8.8.8:443"}; !slices.Equal(calls, want) {
					t.Fatalf("dialed %v, want %v", calls, want)
				}
			})
		})
	}
}

func TestOriginFallbackStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ips := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	calls := 0
	_, err := dialPublicIPs(ctx, ips, "443", func(attempt context.Context, _, _ string) (net.Conn, error) {
		calls++
		cancel()
		return nil, attempt.Err()
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("got %d attempts and %v after cancel", calls, err)
	}
}
