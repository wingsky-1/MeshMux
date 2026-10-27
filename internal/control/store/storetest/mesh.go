package storetest

import (
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/mesh"
)

// MeshSpec returns a valid device specification. The caller decides the purpose
// and the subscriber binding; everything else stays canonical.
func MeshSpec(name string, purpose mesh.Purpose, subscriberID string) mesh.DeviceSpec {
	return mesh.DeviceSpec{
		DisplayName:  name,
		Purpose:      purpose,
		Platform:     mesh.PlatformIOS,
		NodeName:     strings.ToLower(name),
		SubscriberID: subscriberID,
	}
}

// RouteEventKinds returns the audit kinds recorded for one prefix, oldest
// first. The table is append-only, so this is the whole history.
func RouteEventKinds(t *testing.T, s *store.Store, deviceID, prefix string) []string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT kind FROM mesh_route_events WHERE device_id=? AND prefix=? ORDER BY id`, deviceID, prefix)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			t.Fatal(err)
		}
		out = append(out, kind)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// meshSubscriberFixture creates one configured Line and one active subscriber,
// then returns the subscriber id.
func MeshSubscriberFixture(t *testing.T, s *store.Store, now time.Time) string {
	t.Helper()
	line := CreateEdgeNode(t, s, now)
	ConfigureLine(t, s, line, "line-a", now)
	sub, _, err := s.CreateSubscriber("alice", []string{line}, now)
	if err != nil {
		t.Fatal(err)
	}
	return sub.ID
}
