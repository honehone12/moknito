package sys

import (
	"context"
	"moknito/binid"
	"testing"
)

func TestInfo_InfoApp(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	appID, _ := binid.NewRandom()

	// Create App
	sys.ent.Application.Create().
		SetID(appID).
		SetDomain("example.com").
		SetRedirect("sub.com").
		SetName("Test App").
		Save(ctx)

	// Test Success
	res := sys.InfoApp(ctx, appID.String())
	if res.ValidationErr != nil {
		t.Errorf("val err: %v", res.ValidationErr)
	}
	if res.SystemErr != nil {
		t.Errorf("sys err: %v", res.SystemErr)
	}
	if res.Name != "Test App" {
		t.Errorf("wrong name: %s", res.Name)
	}
	if res.Domain != "example.com" {
		t.Errorf("wrong domain: %s", res.Domain)
	}

	// Test Not Found
	randID, _ := binid.NewRandom()

	res = sys.InfoApp(ctx, randID.String())
	if res.ValidationErr == nil {
		t.Error("expected validation error for missing app")
	}
}
