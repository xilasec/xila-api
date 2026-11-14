package scanner

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestDupKeys(t *testing.T) {
	b, _ := os.ReadFile("testdata/openvas_many.xml")
	fs, _ := NewOpenVAS().Parse(bytes.NewReader(b))
	seen := map[string]int{}
	for i, f := range fs {
		l := ""
		if f.Line != nil {
			l = strconv.Itoa(*f.Line)
		}
		k := string(f.Category) + "|" + f.RuleID + "|" + f.FilePath + "|" + f.Package + "|" + l
		if j, ok := seen[k]; ok {
			fmt.Printf("DUP %q\n  a: %q %v\n  b: %q %v\n", k, fs[j].Title, fs[j].Metadata["port"], f.Title, f.Metadata["port"])
		}
		seen[k] = i
	}
}
