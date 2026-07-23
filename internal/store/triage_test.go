package store

import "testing"

func TestUpdateFindingTriage(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.UpdateFindingTriage("not-a-kind", 1, "open", ""); err == nil {
		t.Error("expected error for unknown kind")
	}
	if err := st.UpdateFindingTriage("cors", 1, "not-a-status", ""); err == nil {
		t.Error("expected error for unknown status")
	}
	// Known kind/status, missing row: no error, zero rows affected.
	if err := st.UpdateFindingTriage("cors", 1, "fixed", "reviewed"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
