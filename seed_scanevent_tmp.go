//go:build ignore

package main

import (
	"fmt"
	"log"

	"bbtracker/internal/store"
)

func main() {
	st, err := store.Open("bbtracker_scratch.db")
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	if err := st.SaveScanEvent(6, 1, "changed_asset", "200 · Old Title", "200 · New Title"); err != nil {
		log.Fatal(err)
	}
	events, err := st.ListScanEvents(6)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range events {
		fmt.Printf("kind=%s old=%q new=%q subdomain=%s\n", e.Kind, e.OldValue, e.NewValue, e.Subdomain)
	}
}
