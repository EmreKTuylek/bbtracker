package hackerone

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// hacktivityURL is a var (not const) so tests can point it at httptest.
var hacktivityURL = "https://api.hackerone.com/v1/hackers/hacktivity"

const hacktivityPageSize = 100

// Hacktivity is one disclosed report from HackerOne's Hacktivity feed.
// Summary is HackerOne's generated hacktivity_summary: the Hacker API does
// NOT return the full report body (vulnerability_information) for reports the
// caller doesn't own, so this is the most text available per report.
type Hacktivity struct {
	ID          string
	Title       string
	URL         string
	Program     string
	Weakness    string
	Severity    string
	Bounty      float64
	DisclosedAt string
	Summary     string
}

// flexFloat decodes a JSON number, numeric string, or null (the docs don't
// pin down total_awarded_amount's type).
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case float64:
		*f = flexFloat(x)
	case string:
		n, _ := strconv.ParseFloat(x, 64)
		*f = flexFloat(n)
	}
	return nil
}

type hacktivityResponse struct {
	Data []struct {
		ID         json.Number `json:"id"`
		Attributes struct {
			Title       string    `json:"title"`
			URL         string    `json:"url"`
			DisclosedAt string    `json:"disclosed_at"`
			Severity    string    `json:"severity_rating"`
			CWE         string    `json:"cwe"`
			Awarded     flexFloat `json:"total_awarded_amount"`
			Disclosed   bool      `json:"disclosed"`
		} `json:"attributes"`
		Relationships struct {
			Program struct {
				Data struct {
					Attributes struct {
						Handle string `json:"handle"`
						Name   string `json:"name"`
					} `json:"attributes"`
				} `json:"data"`
			} `json:"program"`
			Generated struct {
				Data struct {
					Attributes struct {
						Summary string `json:"hacktivity_summary"`
					} `json:"attributes"`
				} `json:"data"`
			} `json:"report_generated_content"`
		} `json:"relationships"`
	} `json:"data"`
}

// FetchHacktivity pages through disclosed reports, newest first, until an
// empty page or maxPages. Items whose attributes.disclosed is false are
// dropped client-side, since the server-side `disclosed:true` filter value is
// not documented (ponytail: if it's rejected live, the client check still holds).
func FetchHacktivity(ctx context.Context, username, apiToken string, maxPages int) ([]Hacktivity, error) {
	if username == "" || apiToken == "" {
		return nil, fmt.Errorf("hackerone username and api token are required")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	var out []Hacktivity
	for page := 1; page <= maxPages; page++ {
		q := url.Values{}
		q.Set("queryString", "disclosed:true")
		q.Set("sort", "-disclosed_at")
		q.Set("page[number]", strconv.Itoa(page))
		q.Set("page[size]", strconv.Itoa(hacktivityPageSize))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, hacktivityURL+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(username, apiToken)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("hackerone hacktivity: %s", resp.Status)
		}
		var parsed hacktivityResponse
		err = json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode hacktivity response: %w", err)
		}
		if len(parsed.Data) == 0 {
			break
		}
		for _, d := range parsed.Data {
			a := d.Attributes
			if !a.Disclosed {
				continue
			}
			prog := d.Relationships.Program.Data.Attributes
			name := prog.Name
			if name == "" {
				name = prog.Handle
			}
			out = append(out, Hacktivity{
				ID: d.ID.String(), Title: a.Title, URL: a.URL, Program: name, Weakness: a.CWE,
				Severity: a.Severity, Bounty: float64(a.Awarded), DisclosedAt: a.DisclosedAt,
				Summary: d.Relationships.Generated.Data.Attributes.Summary,
			})
		}
	}
	return out, nil
}
