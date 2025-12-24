package sys

import (
	"context"
	"moknito/binid"
	"moknito/ent"
	"moknito/ent/application"
)

type InfoSys interface {
	InfoApp(
		ctx context.Context,
		id string,
	) *InfoAppResult
}

type InfoAppResult struct {
	Name   string
	Domain string
	E
}

func (s *EntRdsSys) InfoApp(
	ctx context.Context,
	appUiid string,
) *InfoAppResult {
	r := &InfoAppResult{}

	id, err := binid.FromUUIDString(appUiid)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	app, err := s.ent.Application.Query().
		Where(
			application.ID(id),
			application.DeletedAtIsNil(),
		).
		Select(
			application.FieldName,
			application.FieldDomain,
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	r.Name = app.Name
	r.Domain = app.Domain
	return r
}
