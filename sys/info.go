package sys

import (
	"context"
	"moknito/ent"
	"moknito/ent/application"
	"moknito/id"
)

type InfoSys interface {
	InfoApp(
		ctx context.Context,
		id string,
	) (*ent.Application, error, error)
}

// (!) returns application, validation error, system error
func (s *EntRdsSys) InfoApp(
	ctx context.Context,
	appUiid string,
) (*ent.Application, error, error) {
	id, err := id.FromUUIDString(appUiid)
	if err != nil {
		return nil, err, nil
	}

	a, err := s.ent.Application.Query().
		Where(
			application.ID(string(id)),
			application.DeletedAtIsNil(),
		).
		Select(
			application.FieldName,
			application.FieldDomain,
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, err, nil
	} else if err != nil {
		return nil, nil, err
	}

	return a, nil, nil
}
