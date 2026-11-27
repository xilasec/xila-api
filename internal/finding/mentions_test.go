package finding

import (
	"reflect"
	"testing"
)

func TestExtractMentions(t *testing.T) {
	candidates := []MentionCandidate{
		{UserID: "u1", Email: "Alice@Example.com"},
		{UserID: "u2", Email: "bob@example.com"},
		{UserID: "u3", Email: "bob@other.com"}, // shares the "bob" local part with u2
	}
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"full email, case-insensitive", "ping @ALICE@example.com please", []string{"u1"}},
		{"bare handle by local part", "cc @alice", []string{"u1"}},
		{"ambiguous local part ignored", "cc @bob", nil},
		{"full email disambiguates", "cc @bob@other.com", []string{"u3"}},
		{"unknown handle ignored", "cc @nobody", nil},
		{"repeated mention deduped", "@alice and again @alice@example.com", []string{"u1"}},
		{"two distinct mentions, in order", "@alice then @bob@other.com", []string{"u1", "u3"}},
		{"no mentions", "just a comment, no handles here", nil},
		{"trailing punctuation not part of the handle", "thanks @alice!", []string{"u1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractMentions(tc.body, candidates)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ExtractMentions(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestExtractMentionsNoCandidates(t *testing.T) {
	if got := ExtractMentions("@alice hi", nil); got != nil {
		t.Errorf("ExtractMentions with no candidates = %v, want nil", got)
	}
}
