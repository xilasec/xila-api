package finding

import "testing"

func TestSourceURL(t *testing.T) {
	line := 42
	const sha = "0123456789abcdef0123456789abcdef01234567"
	for _, tc := range []struct {
		name, repo, ref, path string
		line                  *int
		want                  string
	}{
		{"github", "https://github.com/acme/web.git", sha, "./src/app.go", &line,
			"https://github.com/acme/web/blob/" + sha + "/src/app.go#L42"},
		{"github ssh remote, branch, no line", "git@github.com:acme/web.git", "main", "src/app.go", nil,
			"https://github.com/acme/web/blob/main/src/app.go"},
		{"GitHub Enterprise", "https://github.acme.io/team/api/", "", "/cmd/main.go", &line,
			"https://github.acme.io/team/api/blob/HEAD/cmd/main.go#L42"},
		{"gitlab (self-hosted, subgroup)", "https://gitlab.acme.io/grp/sub/web", sha, "a b.py", &line,
			"https://gitlab.acme.io/grp/sub/web/-/blob/" + sha + "/a%20b.py#L42"},
		{"bitbucket", "https://bitbucket.org/acme/web", sha, "x.js", &line,
			"https://bitbucket.org/acme/web/src/" + sha + "/x.js#lines-42"},
		{"azure devops", "https://dev.azure.com/acme/proj/_git/web", sha, "x.cs", &line,
			"https://dev.azure.com/acme/proj/_git/web?line=42&lineEnd=42&lineEndColumn=1&lineStartColumn=1&path=%2Fx.cs&version=GC" + sha},
		{"codeberg, branch", "https://codeberg.org/acme/web", "main", "x.rs", &line,
			"https://codeberg.org/acme/web/src/branch/main/x.rs#L42"},
		{"credentials stripped", "https://user:tok@github.com/acme/web", "main", "x", nil,
			"https://github.com/acme/web/blob/main/x"},
	} {
		got, ok := SourceURL(tc.repo, tc.ref, tc.path, tc.line)
		if !ok || got != tc.want {
			t.Errorf("%s:\n got %q (%v)\nwant %q", tc.name, got, ok, tc.want)
		}
	}
	for _, tc := range []struct{ name, repo, path string }{
		{"unknown forge", "https://git.example.com/acme/web", "x.go"},
		{"script URL", "javascript:alert(1)//github.com/x", "x.go"},
		{"no repo", "", "x.go"},
		{"path escapes the repo", "https://github.com/acme/web", "../../etc/passwd"},
		{"not a repo path", "https://github.com/acme/web", "https://example.com/x"},
	} {
		if got, ok := SourceURL(tc.repo, "main", tc.path, &line); ok {
			t.Errorf("%s: got a link %q", tc.name, got)
		}
	}
}
