package authui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriters exercises all three served screens: it proves the consent template
// parses (template.Must would otherwise panic at init), that user-supplied values
// are HTML-escaped, and that the callback keeps its meta-refresh to /console.
func TestWriters(t *testing.T) {
	t.Run("consent", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteConsent(w, "Acme <Client>", "https://app/cb?x=1", map[string]string{"state": "s&1"})
		got := w.Body.String()
		if !strings.Contains(got, "Acme &lt;Client&gt;") {
			t.Errorf("client name not escaped:\n%s", got)
		}
		if !strings.Contains(got, `name="approve" value="yes"`) || !strings.Contains(got, `name="approve" value="no"`) {
			t.Error("consent POST contract (approve=yes|no) missing")
		}
		if !strings.Contains(got, `name="state" value="s&amp;1"`) {
			t.Error("replayed hidden field missing or unescaped")
		}
	})
	t.Run("connected", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteConnected(w, "svc <b>")
		got := w.Body.String()
		if !strings.Contains(got, "svc &lt;b&gt;") {
			t.Errorf("name not escaped:\n%s", got)
		}
		if !strings.Contains(got, `content="2;url=/console"`) {
			t.Error("meta-refresh to /console missing")
		}
	})
	t.Run("message", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteMessage(w, "gone <script>")
		got := w.Body.String()
		if !strings.Contains(got, "gone &lt;script&gt;") {
			t.Errorf("message not escaped:\n%s", got)
		}
		if !strings.Contains(got, `href="/console"`) {
			t.Error("console link missing")
		}
	})
}
