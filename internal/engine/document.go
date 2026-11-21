package engine

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/24Bit-System/kilhook/internal/format"
)

// KV is one header or query row, kept ordered so the editor does not shuffle
// the file under the user's cursor.
type KV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AuthDoc mirrors the auth block for the editor.
type AuthDoc struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
	In       string `json:"in"`
	Name     string `json:"name"`
	Value    string `json:"value"`
}

// FuzzDoc mirrors the fuzz block. Zero values mean "use the default", which is
// what the file omits anyway.
type FuzzDoc struct {
	Targets            []string `json:"targets"`
	Wordlist           string   `json:"wordlist"`
	Methods            []string `json:"methods"`
	MaxRequests        int      `json:"maxRequests"`
	RateLimit          float64  `json:"rateLimit"`
	PerHostConcurrency int      `json:"perHostConcurrency"`
}

// SpecDoc mirrors the spec block.
type SpecDoc struct {
	Source    string `json:"source"`
	Operation string `json:"operation"`
	Baseline  string `json:"baseline"`
}

// Document is a .kh file in a shape a form can edit without knowing YAML.
type Document struct {
	Path            string   `json:"path"`
	Format          int      `json:"format"`
	Name            string   `json:"name"`
	Method          string   `json:"method"`
	URL             string   `json:"url"`
	Headers         []KV     `json:"headers"`
	Query           []KV     `json:"query"`
	Auth            AuthDoc  `json:"auth"`
	Fuzz            FuzzDoc  `json:"fuzz"`
	Spec            SpecDoc  `json:"spec"`
	TimeoutMS       int      `json:"timeoutMs"`
	FollowRedirects bool     `json:"followRedirects"`
	Body            string   `json:"body"`
	Warnings        []string `json:"warnings"`
	UnknownFields   []string `json:"unknownFields"`
}

// LoadDocument reads a .kh file into the editor shape. The read is bounded
// before it reaches memory: a workspace can be cloned from anywhere, and an
// oversized file must not be read just because the user clicked it.
func LoadDocument(path string) (*Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, format.MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(data) > format.MaxFileBytes {
		return nil, fmt.Errorf("reading %s: exceeds the %d byte limit", path, format.MaxFileBytes)
	}
	file, warnings, err := format.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	doc := &Document{
		Path:            path,
		Format:          file.Format,
		Name:            file.Name,
		Method:          file.Method,
		URL:             file.URL,
		Headers:         sortedKV(file.Headers),
		Query:           sortedKV(file.Query),
		TimeoutMS:       file.TimeoutMS,
		FollowRedirects: file.Redirects(),
		Body:            string(file.Body),
		Warnings:        warnings,
	}
	if file.Auth != nil {
		doc.Auth = AuthDoc{
			Type:     file.Auth.Type,
			Username: file.Auth.Username,
			Password: file.Auth.Password,
			Token:    file.Auth.Token,
			In:       file.Auth.In,
			Name:     file.Auth.Name,
			Value:    file.Auth.Value,
		}
	} else {
		doc.Auth.Type = format.AuthNone
	}
	if file.Fuzz != nil {
		doc.Fuzz = FuzzDoc{
			Targets:            append([]string{}, file.Fuzz.Targets...),
			Wordlist:           file.Fuzz.Wordlist,
			Methods:            append([]string{}, file.Fuzz.Methods...),
			MaxRequests:        file.Fuzz.MaxRequests,
			RateLimit:          file.Fuzz.RateLimit,
			PerHostConcurrency: file.Fuzz.PerHostConcurrency,
		}
	}
	if file.Spec != nil {
		doc.Spec = SpecDoc{Source: file.Spec.Source, Operation: file.Spec.Operation, Baseline: file.Spec.Baseline}
	}
	for _, w := range warnings {
		if strings.Contains(w, "unknown field") {
			doc.UnknownFields = append(doc.UnknownFields, w)
		}
	}
	return doc, nil
}

// SaveDocument writes the editor's document back through the canonical
// serializer. It reparses what it is about to write first, so a save can never
// leave a file this build cannot load.
func SaveDocument(doc Document) (*Document, error) {
	path := strings.TrimSpace(doc.Path)
	if path == "" {
		return nil, fmt.Errorf("no file to save")
	}
	file, err := doc.toFile()
	if err != nil {
		return nil, err
	}
	data, err := file.Marshal()
	if err != nil {
		return nil, err
	}
	if _, _, err := format.Parse(data); err != nil {
		return nil, fmt.Errorf("refusing to save: the result would not parse: %w", err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// Preserve the existing mode: os.CreateTemp creates 0600, so a naive
	// rename would silently strip group/other permissions from a file the
	// user may share with their editor or teammates.
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(abs); statErr == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".kh-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	return LoadDocument(path)
}

func (d Document) toFile() (*format.File, error) {
	if d.Format != 0 && d.Format != format.Version {
		return nil, fmt.Errorf("format: unsupported version %d", d.Format)
	}
	file := &format.File{
		Format: format.Version,
		Name:   strings.TrimSpace(d.Name),
		Method: strings.ToUpper(strings.TrimSpace(d.Method)),
		URL:    strings.TrimSpace(d.URL),
		Body:   []byte(d.Body),
	}
	if file.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if file.Method == "" {
		return nil, fmt.Errorf("method is required")
	}
	if file.URL == "" {
		return nil, fmt.Errorf("url is required")
	}

	headers := map[string]string{}
	for _, kv := range d.Headers {
		name := strings.TrimSpace(kv.Name)
		if name == "" {
			continue
		}
		headers[name] = kv.Value
	}
	if len(headers) > 0 {
		file.Headers = headers
	}
	query := map[string]string{}
	for _, kv := range d.Query {
		name := strings.TrimSpace(kv.Name)
		if name == "" {
			continue
		}
		query[name] = kv.Value
	}
	if len(query) > 0 {
		file.Query = query
	}

	authType := d.Auth.Type
	if authType == "" {
		authType = format.AuthNone
	}
	if authType != format.AuthNone {
		auth := &format.Auth{Type: authType}
		switch authType {
		case format.AuthBasic:
			auth.Username, auth.Password = d.Auth.Username, d.Auth.Password
		case format.AuthBearer:
			auth.Token = d.Auth.Token
		case format.AuthAPIKey:
			auth.In, auth.Name, auth.Value = d.Auth.In, d.Auth.Name, d.Auth.Value
		default:
			return nil, fmt.Errorf("auth: unknown type %q", authType)
		}
		file.Auth = auth
	}

	if d.TimeoutMS > 0 && d.TimeoutMS != format.DefaultTimeoutMS {
		file.TimeoutMS = d.TimeoutMS
	}
	if !d.FollowRedirects {
		f := false
		file.FollowRedirects = &f
	}

	// Only the fields that differ from the documented defaults are written, so
	// opening and saving a file does not bloat it with values the parser would
	// have supplied anyway.
	hasTargets := false
	for _, t := range d.Fuzz.Targets {
		if strings.TrimSpace(t) != "" {
			hasTargets = true
			break
		}
	}
	if hasTargets || d.Fuzz.Wordlist != "" || len(d.Fuzz.Methods) > 0 ||
		d.Fuzz.MaxRequests > 0 || d.Fuzz.RateLimit > 0 || d.Fuzz.PerHostConcurrency > 0 {
		fuzz := &format.Fuzz{}
		for _, t := range d.Fuzz.Targets {
			if t = strings.TrimSpace(t); t != "" {
				fuzz.Targets = append(fuzz.Targets, t)
			}
		}
		if d.Fuzz.Wordlist != "" && !strings.EqualFold(d.Fuzz.Wordlist, "default") {
			fuzz.Wordlist = d.Fuzz.Wordlist
		}
		if !sameStrings(d.Fuzz.Methods, []string{"injection"}) {
			fuzz.Methods = append([]string{}, d.Fuzz.Methods...)
		}
		if d.Fuzz.MaxRequests > 0 && d.Fuzz.MaxRequests != format.DefaultMaxRequests {
			fuzz.MaxRequests = d.Fuzz.MaxRequests
		}
		if d.Fuzz.RateLimit > 0 && d.Fuzz.RateLimit != format.DefaultRateLimit {
			fuzz.RateLimit = d.Fuzz.RateLimit
		}
		if d.Fuzz.PerHostConcurrency > 0 && d.Fuzz.PerHostConcurrency != format.DefaultPerHost {
			fuzz.PerHostConcurrency = d.Fuzz.PerHostConcurrency
		}
		file.Fuzz = fuzz
	}

	if strings.TrimSpace(d.Spec.Source) != "" || strings.TrimSpace(d.Spec.Operation) != "" || strings.TrimSpace(d.Spec.Baseline) != "" {
		file.Spec = &format.Spec{
			Source:    strings.TrimSpace(d.Spec.Source),
			Operation: strings.TrimSpace(d.Spec.Operation),
			Baseline:  strings.TrimSpace(d.Spec.Baseline),
		}
	}

	return file, nil
}

func sortedKV(in map[string]string) []KV {
	out := make([]KV, 0, len(in))
	for k, v := range in {
		out = append(out, KV{Name: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
