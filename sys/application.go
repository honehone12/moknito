package sys

import (
	"context"
	"encoding/base64"
	"moknito/ent"
	"moknito/ent/application"
)

type AppSys interface {
	ApplicationInfomation(
		ctx context.Context,
		id string,
	) (*ent.Application, bool, error)
}

func (s *EntRdsSys) ApplicationInfomation(
	ctx context.Context,
	id string,
) (*ent.Application, bool, error) {
	dec, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return nil, false, err
	}

	a, err := s.ent.Application.Query().
		Where(
			application.ID(string(dec)),
			application.DeletedAtIsNil(),
		).
		Select(
			application.FieldName,
			application.FieldDomain,
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}

	return a, true, nil
}
