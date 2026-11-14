package demo

import (
	"errors"
	"testing"
)

func TestCheckEnvironment(t *testing.T) {
	cases := []struct {
		name         string
		isProduction bool
		force        bool
		wantErr      bool
	}{
		{"development, no force", false, false, false},
		{"development, force", false, true, false},
		{"production, no force refused", true, false, true},
		{"production, forced allowed", true, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckEnvironment(c.isProduction, c.force)
			if c.wantErr && !errors.Is(err, ErrProductionRefused) {
				t.Errorf("CheckEnvironment(%v, %v) = %v, want ErrProductionRefused", c.isProduction, c.force, err)
			}
			if !c.wantErr && err != nil {
				t.Errorf("CheckEnvironment(%v, %v) = %v, want nil", c.isProduction, c.force, err)
			}
		})
	}
}
