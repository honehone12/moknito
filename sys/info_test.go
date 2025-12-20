package sys

import (
	"context"
	"moknito/id"
	"testing"
)

func TestInfo_InfoApp(t *testing.T) {
	sys, _ := setupSys(t)
	defer sys.Close()
	ctx := context.Background()

	appID, _ := id.NewRandom()
	appUuid, _ := appID.ToUUID()

	// Create App
	sys.ent.Application.Create().
		SetID(string(appID)).
		SetDomain("example.com").
		SetRedirect("sub").
		SetName("Test App").
		Save(ctx)

	// Test Success
	res := sys.InfoApp(ctx, appUuid.String())
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
	randID, _ := id.NewRandom()
	randUuid, _ := randID.ToUUID()
	res = sys.InfoApp(ctx, randUuid.String())
	if res.ValidationErr == nil {
		t.Error("expected validation error for missing app")
	}
}
