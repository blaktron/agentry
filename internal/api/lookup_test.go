package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/config"
)

// A handle lookup that fails is not a handle that is absent (agentry#261):
// the site takes 404 as "nobody holds this handle", so a query error must
// answer 500 and only a missing row 404.
func TestLookupFailedDistinguishesAbsenceFromError(t *testing.T) {
	s := New(config.Default(), nil, nil)
	cases := []struct {
		name string
		err  error
		want int // 0: nothing written
	}{
		{"no error writes nothing", nil, 0},
		{"no rows is 404", pgx.ErrNoRows, http.StatusNotFound},
		{"a wrapped no-rows is 404", errors.Join(errors.New("get user: "), pgx.ErrNoRows), http.StatusNotFound},
		{"a query error is 500", errors.New("dial tcp: connection refused"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/users/x", nil)
			wrote := s.lookupFailed(rec, req, "user", c.err)
			if c.want == 0 {
				if wrote {
					t.Fatalf("wrote %d for a nil error", rec.Code)
				}
				return
			}
			if !wrote || rec.Code != c.want {
				t.Fatalf("wrote=%v status=%d, want %d", wrote, rec.Code, c.want)
			}
		})
	}
}
