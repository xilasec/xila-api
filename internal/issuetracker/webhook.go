package issuetracker

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// WebhookEvent is what one tracker delivery means for Xila (M13 13.18): the
// issue it is about, as Xila links it (Ref.ExternalID), and the comment it
// adds, if any. A state change carries no state: the receiver re-reads the
// issue through the API, so a delivery can only make Xila look, never decide.
type WebhookEvent struct {
	ExternalID string
	Comment    *RemoteComment
}

// RemoteComment is a comment written in the tracker.
type RemoteComment struct {
	ID, Author, Body string
}

// Webhook errors. ErrWebhookAuth: the delivery is not from the tracker (bad
// or missing signature/secret); ErrWebhookPayload: it is, but unreadable.
var (
	ErrWebhookAuth    = errors.New("webhook signature or secret invalid")
	ErrWebhookPayload = errors.New("webhook payload invalid")
)

// webhookMaxAge bounds how old a timestamped delivery (Linear) may be, so a
// captured one can't be replayed later. Replays inside it are harmless: state
// is re-read, comments are taken in once.
const webhookMaxAge = 5 * time.Minute

// VerifyWebhook checks that a delivery came from the tracker, with each
// tracker's own mechanism. header reads one request header.
func VerifyWebhook(kind Kind, header func(string) string, body []byte, secret string) error {
	if secret == "" {
		return ErrWebhookAuth
	}
	ok := false
	switch kind {
	case KindGitHub: // https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
		ok = hmacHex(header("X-Hub-Signature-256"), "sha256=", body, secret)
	case KindJira: // https://developer.atlassian.com/cloud/jira/platform/webhooks/#secure-admin-webhooks
		ok = hmacHex(header("X-Hub-Signature"), "sha256=", body, secret)
	case KindLinear: // https://linear.app/developers/webhooks#securing-webhooks
		ok = hmacHex(header("Linear-Signature"), "", body, secret)
	case KindGitLab: // https://docs.gitlab.com/user/project/integrations/webhooks/#custom-headers (secret token)
		ok = equal(header("X-Gitlab-Token"), secret)
	case KindAzureDevOps: // service hook basic authentication: the password is the secret
		if raw, found := strings.CutPrefix(header("Authorization"), "Basic "); found {
			if dec, err := base64.StdEncoding.DecodeString(raw); err == nil {
				_, pass, _ := strings.Cut(string(dec), ":")
				ok = equal(pass, secret)
			}
		}
	case KindServiceNow: // a REST message from a business rule, documented in the README
		token, found := strings.CutPrefix(header("Authorization"), "Bearer ")
		ok = found && equal(token, secret)
	}
	if !ok {
		return ErrWebhookAuth
	}
	return nil
}

func hmacHex(got, prefix string, body []byte, secret string) bool {
	sig, found := strings.CutPrefix(strings.TrimSpace(got), prefix)
	if !found {
		return false
	}
	want, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// ParseWebhook reads a verified delivery. ok=false: an event Xila doesn't act
// on (a ping, a pull-request comment, another entity).
func ParseWebhook(kind Kind, header func(string) string, body []byte, now time.Time) (ev WebhookEvent, ok bool, err error) {
	switch kind {
	case KindGitHub:
		return parseGitHub(header("X-GitHub-Event"), body)
	case KindGitLab:
		return parseGitLab(header("X-Gitlab-Event"), body)
	case KindJira:
		return parseJira(body)
	case KindAzureDevOps:
		return parseAzure(body)
	case KindLinear:
		return parseLinear(body, now)
	case KindServiceNow:
		return parseServiceNow(body)
	}
	return WebhookEvent{}, false, ErrWebhookPayload
}

func decode(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return ErrWebhookPayload
	}
	return nil
}

// https://docs.github.com/en/webhooks/webhook-events-and-payloads#issues
// https://docs.github.com/en/webhooks/webhook-events-and-payloads#issue_comment
func parseGitHub(event string, body []byte) (WebhookEvent, bool, error) {
	var p struct {
		Action string `json:"action"`
		Issue  struct {
			Number      int             `json:"number"`
			PullRequest json.RawMessage `json:"pull_request"`
		} `json:"issue"`
		Comment struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
			User struct {
				Login string `json:"login"`
			} `json:"user"`
		} `json:"comment"`
	}
	if event != "issues" && event != "issue_comment" {
		return WebhookEvent{}, false, nil
	}
	if err := decode(body, &p); err != nil {
		return WebhookEvent{}, false, err
	}
	if p.Issue.Number == 0 || p.Issue.PullRequest != nil {
		return WebhookEvent{}, false, nil
	}
	ev := WebhookEvent{ExternalID: strconv.Itoa(p.Issue.Number)}
	if event == "issue_comment" {
		if p.Action != "created" {
			return WebhookEvent{}, false, nil
		}
		ev.Comment = &RemoteComment{ID: strconv.FormatInt(p.Comment.ID, 10), Author: p.Comment.User.Login, Body: p.Comment.Body}
	}
	return ev, true, nil
}

// https://docs.gitlab.com/user/project/integrations/webhook_events/#work-item-events
// https://docs.gitlab.com/user/project/integrations/webhook_events/#comment-on-a-work-item
func parseGitLab(event string, body []byte) (WebhookEvent, bool, error) {
	var p struct {
		ObjectAttributes struct {
			ID           int64  `json:"id"`
			IID          int    `json:"iid"`
			Note         string `json:"note"`
			NoteableType string `json:"noteable_type"`
		} `json:"object_attributes"`
		Issue struct {
			IID int `json:"iid"`
		} `json:"issue"`
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	}
	switch event {
	case "Issue Hook":
		if err := decode(body, &p); err != nil {
			return WebhookEvent{}, false, err
		}
		if p.ObjectAttributes.IID == 0 {
			return WebhookEvent{}, false, nil
		}
		return WebhookEvent{ExternalID: strconv.Itoa(p.ObjectAttributes.IID)}, true, nil
	case "Note Hook":
		if err := decode(body, &p); err != nil {
			return WebhookEvent{}, false, err
		}
		if p.ObjectAttributes.NoteableType != "Issue" || p.Issue.IID == 0 {
			return WebhookEvent{}, false, nil
		}
		return WebhookEvent{ExternalID: strconv.Itoa(p.Issue.IID), Comment: &RemoteComment{
			ID: strconv.FormatInt(p.ObjectAttributes.ID, 10), Author: p.User.Name, Body: p.ObjectAttributes.Note,
		}}, true, nil
	}
	return WebhookEvent{}, false, nil
}

// https://developer.atlassian.com/cloud/jira/platform/webhooks/#example-callback-for-an-issue-related-event
func parseJira(body []byte) (WebhookEvent, bool, error) {
	var p struct {
		WebhookEvent string `json:"webhookEvent"`
		Issue        struct {
			Key string `json:"key"`
		} `json:"issue"`
		Comment struct {
			ID     string `json:"id"`
			Body   string `json:"body"`
			Author struct {
				DisplayName string `json:"displayName"`
			} `json:"author"`
		} `json:"comment"`
	}
	if err := decode(body, &p); err != nil {
		return WebhookEvent{}, false, err
	}
	if p.Issue.Key == "" {
		return WebhookEvent{}, false, nil
	}
	ev := WebhookEvent{ExternalID: p.Issue.Key}
	switch p.WebhookEvent {
	case "jira:issue_updated":
	case "comment_created":
		ev.Comment = &RemoteComment{ID: p.Comment.ID, Author: p.Comment.Author.DisplayName, Body: p.Comment.Body}
	default:
		return WebhookEvent{}, false, nil
	}
	return ev, true, nil
}

// htmlTag strips markup from an Azure DevOps comment (stored as HTML).
var htmlTag = regexp.MustCompile(`<[^>]*>`)

// https://learn.microsoft.com/en-us/azure/devops/service-hooks/events#workitem.updated
// https://learn.microsoft.com/en-us/azure/devops/service-hooks/events#workitem.commented
func parseAzure(body []byte) (WebhookEvent, bool, error) {
	var p struct {
		EventType string `json:"eventType"`
		Resource  struct {
			ID         int                        `json:"id"`
			WorkItemID int                        `json:"workItemId"`
			Rev        int                        `json:"rev"`
			Fields     map[string]json.RawMessage `json:"fields"`
		} `json:"resource"`
	}
	if err := decode(body, &p); err != nil {
		return WebhookEvent{}, false, err
	}
	switch p.EventType {
	case "workitem.updated":
		if p.Resource.WorkItemID == 0 {
			return WebhookEvent{}, false, nil
		}
		return WebhookEvent{ExternalID: strconv.Itoa(p.Resource.WorkItemID)}, true, nil
	case "workitem.commented":
		if p.Resource.ID == 0 {
			return WebhookEvent{}, false, nil
		}
		var text string
		_ = json.Unmarshal(p.Resource.Fields["System.History"], &text)
		text = strings.TrimSpace(htmlTag.ReplaceAllString(text, ""))
		if text == "" {
			return WebhookEvent{}, false, nil
		}
		return WebhookEvent{ExternalID: strconv.Itoa(p.Resource.ID), Comment: &RemoteComment{
			ID: "rev-" + strconv.Itoa(p.Resource.Rev), Author: azureIdentity(p.Resource.Fields["System.ChangedBy"]), Body: text,
		}}, true, nil
	}
	return WebhookEvent{}, false, nil
}

// azureIdentity reads an identity field: "Name <email>" or {"displayName"}.
func azureIdentity(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		name, _, _ := strings.Cut(s, " <")
		return strings.TrimSpace(name)
	}
	var o struct {
		DisplayName string `json:"displayName"`
	}
	_ = json.Unmarshal(raw, &o)
	return o.DisplayName
}

// linearIdentifier finds the issue identifier (ENG-123, how Xila links a
// Linear issue) in a payload url: a comment's data has only the issue uuid.
var linearIdentifier = regexp.MustCompile(`/issue/([A-Za-z0-9]+-[0-9]+)(?:[/#?]|$)`)

// https://linear.app/developers/webhooks#data-change-events-payload
func parseLinear(body []byte, now time.Time) (WebhookEvent, bool, error) {
	var p struct {
		Action           string `json:"action"`
		Type             string `json:"type"`
		URL              string `json:"url"`
		WebhookTimestamp int64  `json:"webhookTimestamp"`
		Actor            struct {
			Name string `json:"name"`
		} `json:"actor"`
		Data struct {
			ID   string `json:"id"`
			Body string `json:"body"`
		} `json:"data"`
	}
	if err := decode(body, &p); err != nil {
		return WebhookEvent{}, false, err
	}
	if age := now.Sub(time.UnixMilli(p.WebhookTimestamp)); age > webhookMaxAge || age < -webhookMaxAge {
		return WebhookEvent{}, false, ErrWebhookAuth
	}
	m := linearIdentifier.FindStringSubmatch(p.URL)
	if m == nil {
		return WebhookEvent{}, false, nil
	}
	ev := WebhookEvent{ExternalID: m[1]}
	switch {
	case p.Type == "Issue" && p.Action == "update":
	case p.Type == "Comment" && p.Action == "create" && p.Data.ID != "":
		ev.Comment = &RemoteComment{ID: p.Data.ID, Author: p.Actor.Name, Body: p.Data.Body}
	default:
		return WebhookEvent{}, false, nil
	}
	return ev, true, nil
}

// parseServiceNow reads the payload documented for a business rule's REST
// message: {"sys_id": "..."} for a change, plus "comment": {"id", "author",
// "body"} for a new work note or comment.
func parseServiceNow(body []byte) (WebhookEvent, bool, error) {
	var p struct {
		SysID   string `json:"sys_id"`
		Comment *struct {
			ID     string `json:"id"`
			Author string `json:"author"`
			Body   string `json:"body"`
		} `json:"comment"`
	}
	if err := decode(body, &p); err != nil {
		return WebhookEvent{}, false, err
	}
	if p.SysID == "" {
		return WebhookEvent{}, false, nil
	}
	ev := WebhookEvent{ExternalID: p.SysID}
	if p.Comment != nil && p.Comment.ID != "" {
		ev.Comment = &RemoteComment{ID: p.Comment.ID, Author: p.Comment.Author, Body: p.Comment.Body}
	}
	return ev, true, nil
}
