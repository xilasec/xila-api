package customfield

import (
	"context"
	"reflect"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// accessChecker answers whether a user can see a project (membership.Repository
// satisfies it).
type accessChecker interface {
	RoleOnProject(ctx context.Context, userID, projectID string) (domain.TeamRole, bool, error)
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
}

// findingWriter writes a finding's values in a transaction attributed to
// actor, so the change lands in the finding's history (finding.Repository).
type findingWriter interface {
	SetCustom(ctx context.Context, id string, set map[string]any, unset []string, actor, note string) (map[string]any, error)
}

// Service validates and writes custom-field values.
type Service struct {
	repo     *Repository
	access   accessChecker
	findings findingWriter
}

// NewService constructs a Service.
func NewService(repo *Repository, access accessChecker, findings findingWriter) *Service {
	return &Service{repo: repo, access: access, findings: findings}
}

// Change is a validated write: Set merges into the entity's values, Unset
// removes keys; Result is the values once it is applied.
type Change struct {
	Set    map[string]any
	Unset  []string
	Result map[string]any
}

// Empty reports whether the change leaves the values as they are.
func (c Change) Empty() bool { return len(c.Set) == 0 && len(c.Unset) == 0 }

// Prepare validates patch (key → value, null = unset) for one entity against
// the definitions that apply to it: every key must be a defined field of this
// entity (and of its organization), every value must fit the field's type,
// and a user field may only name someone who can see the entity's project.
// With requireAll (a person's edit), every required field must be set
// afterwards; system writers only may not clear one.
func (s *Service) Prepare(ctx context.Context, entity Entity, id string, patch map[string]any, requireAll bool) (Change, error) {
	t, err := s.repo.Target(ctx, entity, id)
	if err != nil {
		return Change{}, err
	}
	defs, err := s.repo.List(ctx, entity)
	if err != nil {
		return Change{}, err
	}
	byKey := map[string]Definition{}
	for _, d := range defs {
		if d.AppliesTo(t.OrgID) {
			byKey[d.Key] = d
		}
	}
	ch := Change{Set: map[string]any{}, Unset: []string{}, Result: map[string]any{}}
	for k, v := range t.Custom {
		ch.Result[k] = v
	}
	keys := make([]string, 0, len(patch))
	for k := range patch {
		keys = append(keys, k)
	}
	slices.Sort(keys) // deterministic first error
	for _, k := range keys {
		d, ok := byKey[k]
		if !ok {
			return Change{}, invalid("unknown custom field %q for this %s", k, entity)
		}
		if d.Computed {
			return Change{}, invalid("%s is computed and can't be set directly", k)
		}
		v, err := d.Normalize(patch[k])
		if err != nil {
			return Change{}, err
		}
		if v == nil {
			if _, had := ch.Result[k]; had {
				ch.Unset = append(ch.Unset, k)
				delete(ch.Result, k)
			}
			continue
		}
		if d.Type == TypeUser {
			if err := s.canSee(ctx, v.(string), t.ProjectID, k); err != nil {
				return Change{}, err
			}
		}
		if cur, had := ch.Result[k]; had && reflect.DeepEqual(cur, v) {
			continue
		}
		ch.Set[k] = v
		ch.Result[k] = v
	}
	var missing []string
	for _, d := range byKey {
		if !d.Required {
			continue
		}
		_, set := ch.Result[d.Key]
		if !set && (requireAll || slices.Contains(ch.Unset, d.Key)) {
			missing = append(missing, d.Key)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return Change{}, invalid("required custom field(s) must be set: %s", strings.Join(missing, ", "))
	}
	return ch, nil
}

// canSee: a user field names someone who can see the project — an instance
// admin, or anyone with a role on it (membership.ProjectGrantsSQL).
func (s *Service) canSee(ctx context.Context, userID, projectID, key string) error {
	isAdmin, _, err := s.access.AdminStatus(ctx, userID)
	if err != nil {
		return err
	}
	if isAdmin {
		return nil
	}
	_, ok, err := s.access.RoleOnProject(ctx, userID, projectID)
	if err != nil {
		return err
	}
	if !ok {
		return invalid("%s: that user can't see this project", key)
	}
	return nil
}

// Set validates patch and writes it as actor. It returns the entity's values
// afterwards.
func (s *Service) Set(ctx context.Context, entity Entity, id string, patch map[string]any, actor string) (map[string]any, error) {
	ch, err := s.Prepare(ctx, entity, id, patch, true)
	if err != nil {
		return nil, err
	}
	if ch.Empty() {
		return ch.Result, nil
	}
	if entity == EntityFinding {
		return s.findings.SetCustom(ctx, id, ch.Set, ch.Unset, actor, "edited custom fields")
	}
	return s.repo.SetValues(ctx, entity, id, ch.Set, ch.Unset)
}
