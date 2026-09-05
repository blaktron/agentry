package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// pqArray scans a Postgres text[] literal ("{a,b}") into a []string without
// pulling a second driver in just for tests. Values here are plain words.
func pqArray(dst *[]string) sql.Scanner { return &textArray{dst: dst} }

type textArray struct{ dst *[]string }

func (a *textArray) Scan(src any) error {
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("text[]: unexpected %T", src)
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
	if s == "" {
		*a.dst = []string{}
		return nil
	}
	*a.dst = strings.Split(s, ",")
	return nil
}
