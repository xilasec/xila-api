package domain

import "slices"

// euMemberStates are the ISO 3166-1 alpha-2 codes of the 27 EU Member States
// (Greece as GR, the ISO code, not the EU's "EL").
var euMemberStates = []string{
	"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU",
	"IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
}

// EUMemberState reports whether code is an EU Member State's ISO 3166-1
// alpha-2 code (upper case).
func EUMemberState(code string) bool { return slices.Contains(euMemberStates, code) }
