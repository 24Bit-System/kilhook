package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadTestSpec(t *testing.T) *Document {
	t.Helper()
	d, err := Load(filepath.Join("..", "..", "testdata", "specs", "petstore.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(d.Warnings) != 0 {
		t.Fatalf("spec warnings: %v", d.Warnings)
	}
	return d
}

func TestMatchOperation(t *testing.T) {
	d := loadTestSpec(t)

	m, err := d.MatchOperation("GET", "/pets/42")
	if err != nil {
		t.Fatal(err)
	}
	if m.SpecPath != "/pets/{id}" || m.Stripped != 0 {
		t.Fatalf("match = %+v", m)
	}

	m, err = d.MatchOperation("post", "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	if m.SpecPath != "/auth/login" {
		t.Fatalf("spec path = %q", m.SpecPath)
	}

	// A server base path in front of the spec path is tolerated.
	m, err = d.MatchOperation("GET", "/v1/pets")
	if err != nil {
		t.Fatal(err)
	}
	if m.SpecPath != "/pets" || m.Stripped != 1 {
		t.Fatalf("match = %+v", m)
	}
}

func TestMatchOperationErrorListsPaths(t *testing.T) {
	d := loadTestSpec(t)
	_, err := d.MatchOperation("DELETE", "/pets")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "/pets/{id}") {
		t.Fatalf("error should list declared paths: %v", err)
	}
}

func TestValidateGoodResponse(t *testing.T) {
	d := loadTestSpec(t)
	m, err := d.MatchOperation("GET", "/pets/42")
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.ValidateResponse(m, 200, "application/json", []byte(`{"id":1,"name":"rex","tag":null,"photoUrls":["a"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("expected OK, got %+v", res)
	}
}

func TestValidateMissingRequiredField(t *testing.T) {
	d := loadTestSpec(t)
	m, _ := d.MatchOperation("GET", "/pets/42")
	res, err := d.ValidateResponse(m, 200, "application/json", []byte(`{"id":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Violations) == 0 {
		t.Fatal("expected a violation for the missing name")
	}
	found := false
	for _, v := range res.Violations {
		if strings.Contains(v.Message, "name") || v.Path == "response.name" || strings.Contains(v.Message, "missing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("violations = %+v", res.Violations)
	}
}

func TestValidateWrongTypeHasReadablePath(t *testing.T) {
	d := loadTestSpec(t)
	m, _ := d.MatchOperation("GET", "/pets")
	res, err := d.ValidateResponse(m, 200, "application/json; charset=utf-8",
		[]byte(`[{"id":1,"name":"a"},{"id":"two","name":"b"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Violations) != 1 {
		t.Fatalf("violations = %+v", res.Violations)
	}
	v := res.Violations[0]
	if v.Path != "response[1].id" {
		t.Fatalf("path = %q, want response[1].id", v.Path)
	}
	if !strings.Contains(v.Message, "string") || !strings.Contains(v.Message, "integer") {
		t.Fatalf("message = %q", v.Message)
	}
}

func TestValidateNullableAcceptsNull(t *testing.T) {
	d := loadTestSpec(t)
	m, _ := d.MatchOperation("POST", "/auth/login")
	res, err := d.ValidateResponse(m, 200, "application/json", []byte(`{"token":"t","expires_in":60,"scope":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("nullable field rejected: %+v", res.Violations)
	}

	res, err = d.ValidateResponse(m, 200, "application/json", []byte(`{"token":"t","expires_in":"60"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Violations) != 1 || res.Violations[0].Path != "response.expires_in" {
		t.Fatalf("violations = %+v", res.Violations)
	}
}

func TestValidateUsesStatusClassAndDefault(t *testing.T) {
	d := loadTestSpec(t)
	m, _ := d.MatchOperation("GET", "/pets/42")
	res, err := d.ValidateResponse(m, 404, "application/json", []byte(`{"message":"no such pet"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.StatusKey != "404" {
		t.Fatalf("res = %+v", res)
	}

	// 500 is not declared: that is a contract violation to report, not a
	// reason to abort the whole run.
	res, err = d.ValidateResponse(m, 500, "application/json", []byte(`{}`))
	if err != nil {
		t.Fatalf("undeclared status must be a violation, not an error: %v", err)
	}
	if len(res.Violations) != 1 {
		t.Fatalf("violations = %+v", res.Violations)
	}
	v := res.Violations[0]
	if v.Path != "response.status" || v.Status != 500 || !strings.Contains(v.Message, "500") {
		t.Fatalf("violation = %+v", v)
	}
	if res.OK() {
		t.Fatal("an undeclared status must not pass")
	}
}

func TestValidateSkipsWhenNoSchema(t *testing.T) {
	d := loadTestSpec(t)
	m, _ := d.MatchOperation("POST", "/auth/login")
	res, err := d.ValidateResponse(m, 200, "text/plain", []byte("not json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped == "" {
		t.Fatalf("expected a skip reason, got %+v", res)
	}
}

func TestValidateInvalidJSONBodySkips(t *testing.T) {
	d := loadTestSpec(t)
	m, _ := d.MatchOperation("GET", "/pets")
	res, err := d.ValidateResponse(m, 200, "application/json", []byte("<html>oops</html>"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Skipped, "not JSON") {
		t.Fatalf("skipped = %q", res.Skipped)
	}
}

func TestLoadRejectsOversizedSpec(t *testing.T) {
	big := strings.Repeat("a", MaxSpecBytes+1)
	dir := t.TempDir()
	path := filepath.Join(dir, "big.yaml")
	if err := writeFile(path, big); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestCompareDrift(t *testing.T) {
	base := []byte(`{"id":1,"name":"a","tag":"x"}`)
	same := []byte(`{"id":1,"name":"b","tag":"x"}`) // value change only
	drifted := []byte(`{"id":1,"name":"a"}`)        // tag removed

	got, err := Compare(base, same)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("value changes are not drift: %+v", got)
	}

	got, err = Compare(base, drifted)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Change != "removed" || got[0].Path != "response.tag" {
		t.Fatalf("drift = %+v", got)
	}
}

func TestSaveAndLoadBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "last-good.json")
	body := []byte(`{"ok":true}`)
	if err := SaveBaseline(path, body); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %q", got)
	}
}

func TestLoadNormalizesUnquotedYAMLStatusKeys(t *testing.T) {
	// The standard YAML style for OpenAPI writes status codes unquoted
	// (`responses:` → `200:`). yaml.v3 resolves those keys as !!int and
	// decodes the subtree into map[any]any; without normalization the raw-tree
	// lookup silently sees no responses at all and the run aborts.
	src := `openapi: 3.0.3
info:
  title: Int keys
  version: "1"
paths:
  /pets:
    get:
      responses:
        200:
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id]
                properties:
                  id:
                    type: integer
`
	path := filepath.Join(t.TempDir(), "int-keys.yaml")
	if err := writeFile(path, src); err != nil {
		t.Fatal(err)
	}
	d, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m, err := d.MatchOperation("GET", "/pets")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	res, err := d.ValidateResponse(m, 200, "application/json", []byte(`{"id":1}`))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !res.OK() {
		t.Fatalf("good response rejected: %+v", res)
	}
	res, err = d.ValidateResponse(m, 200, "application/json", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Violations) == 0 {
		t.Fatal("missing required id must be a violation")
	}
}

func TestMatchOperationRootPath(t *testing.T) {
	// Login/token endpoints are commonly declared as `post: /`; splitPath
	// yields zero segments for "/", and the strip loop must still run once.
	src := `openapi: 3.0.3
info:
  title: Root
  version: "1"
paths:
  /:
    post:
      responses:
        "200":
          description: ok
`
	path := filepath.Join(t.TempDir(), "root.yaml")
	if err := writeFile(path, src); err != nil {
		t.Fatal(err)
	}
	d, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m, err := d.MatchOperation("POST", "/")
	if err != nil {
		t.Fatalf("root path must match: %v", err)
	}
	if m.SpecPath != "/" || m.Stripped != 0 {
		t.Fatalf("match = %+v", m)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
