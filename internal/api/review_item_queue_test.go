package api_test

import (
	"context"
	"net/http"
	"testing"
)

// TestReviewItemOfAnUnknownQueueIsRefused (agentry#413): the access switch
// over a review item's queue refuses what it does not recognise. The DDL's
// CHECK admits only platform and org today; the code must not lean on it,
// because a widened CHECK or an extension-written row would otherwise
// hand an unpublished archive's contents to any signed-in caller. The row
// is forced past the CHECK here, the way a future migration might.
func TestReviewItemOfAnUnknownQueueIsRefused(t *testing.T) {
	env := newTestEnv(t)
	_, itemID, staffSess := setupReviewItem(t, env, "rq")
	ctx := context.Background()
	pool := env.st.Pool()
	if _, err := pool.Exec(ctx, `ALTER TABLE review_items DROP CONSTRAINT review_items_queue_check`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `UPDATE review_items SET queue = 'platform' WHERE id = $1`, itemID)
		_, _ = pool.Exec(ctx, `ALTER TABLE review_items ADD CONSTRAINT review_items_queue_check CHECK (queue IN ('platform','org'))`)
	})
	if _, err := pool.Exec(ctx, `UPDATE review_items SET queue = 'other' WHERE id = $1`, itemID); err != nil {
		t.Fatal(err)
	}

	otherH := env.register("rq-other")
	env.verifyEmail(otherH)
	other := env.login(otherH)
	for name, c := range map[string]caller{"a signed-in stranger": other, "platform staff": staffSess} {
		res := env.do(c, http.MethodGet, "/api/v1/review-items/"+itemID, nil)
		if code, slug, _ := problemOf(t, res); code != http.StatusForbidden {
			t.Fatalf("%s reading a review item of an unknown queue: %d %s, want 403", name, code, slug)
		}
	}
}
