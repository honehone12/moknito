package sys

import (
	"context"
	"moknito/ent"
	"moknito/id"
)

type AppSys interface {
	AppAuthorize(
		ctx context.Context,
		userId id.Id,
		appUuid string,
	) (error, error)
}

// (!) returns validation error, system error (!)
func (s *EntRdsSys) AppAuthorize(
	ctx context.Context,
	userId id.Id,
	appUiid string,
) (error, error) {
	appId, err := id.FromUUIDString(appUiid)
	if err != nil {
		return err, nil
	}

	id, err := id.NewSequential()
	if err != nil {
		return nil, err
	}

	err = s.ent.AuthorizedApp.Create().
		SetID(string(id)).
		SetApplicationID(string(appId)).
		SetUserID(string(userId)).
		Exec(ctx)
	if ent.IsConstraintError(err) {
		return err, nil
	} else if err != nil {
		return nil, err
	}

	return nil, nil
}
