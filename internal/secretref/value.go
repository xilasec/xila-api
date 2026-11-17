package secretref

// Value reads a secret setting's current value. Consumers hold a Value
// instead of the string so a rotated secret (config.Secrets refreshes
// references and NAME_FILE settings) takes effect at the next use without a
// restart. The zero Value reads as "".
type Value func() string

// Get returns the current value ("" for a nil Value).
func (v Value) Get() string {
	if v == nil {
		return ""
	}
	return v()
}

// Static is a Value that never changes (tests, settings that can't rotate).
func Static(s string) Value { return func() string { return s } }
