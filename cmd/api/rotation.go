package main

import (
	"log/slog"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/secretbox"
	"github.com/xilasec/xila-api/internal/sso"
)

// rotatedKeySettings are the secrets whose change re-keys the process: the
// JWT and integration key rings and the environment SSO provider.
var rotatedKeySettings = []string{"JWT_SECRET", "JWT_PREVIOUS_SECRETS", "INTEGRATION_SECRET_KEY",
	"INTEGRATION_SECRET_KEY_PREVIOUS", "OIDC_CLIENT_SECRET"}

// wireKeyRotation applies a rotated JWT_SECRET / INTEGRATION_SECRET_KEY (and
// their _PREVIOUS lists) and OIDC_CLIENT_SECRET without a restart, when
// cfg.Secrets refreshes them: the key rings and the environment SSO provider
// are updated in place. A value that fails boot's checks is refused and the
// running keys stay.
func wireKeyRotation(cfg config.Config, jwt *auth.Keys, ring *secretbox.Keyring, registry *sso.Registry) {
	rotate := func(string) {
		fresh, err := cfg.Refreshed()
		if err != nil {
			slog.Warn("rotated secret refused; keeping the current keys", "error", err)
			return
		}
		primary, _ := fresh.IntegrationKey()
		previous, _ := fresh.IntegrationPreviousKeys()
		if err := ring.Update(primary, previous); err != nil {
			slog.Warn("rotated integration key refused; keeping the current keys", "error", err)
			return
		}
		jwt.Update(fresh.JWT.Secret, fresh.JWT.Previous)
		registry.UpdateEnv(sso.EnvProviders(fresh))
	}
	for _, name := range rotatedKeySettings {
		cfg.Secrets.OnChange(name, rotate)
	}
}
