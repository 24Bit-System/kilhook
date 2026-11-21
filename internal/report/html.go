package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/24Bit-System/kilhook/internal/strx"
)

// HTML renders the report as a standalone file with no external assets.
func (r *Report) HTML() ([]byte, error) {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Text renders a compact terminal report.
func (r *Report) Text() string {
	var b strings.Builder

	verdict := "clean"
	switch {
	case r.ExitCode == 2:
		// Only an aborted run reaches the report with exit 2: engine errors
		// exit from the CLI before any report is rendered.
		verdict = "incomplete"
	case r.ExitCode != 0:
		verdict = "problems found"
	}
	fmt.Fprintf(&b, "kilhook %s — %s\n", r.Version, verdict)
	fmt.Fprintf(&b, "%s %s\n", r.Request.Method, r.Request.URL)

	if r.Response != nil {
		fmt.Fprintf(&b, "response: %d in %dms, %d bytes\n", r.Response.Status, r.Response.DurationMS, r.Response.SizeBytes)
	}

	if r.Spec != nil {
		fmt.Fprintf(&b, "\nspec: %s\n", r.Spec.Operation)
		if r.Spec.Skipped != "" {
			fmt.Fprintf(&b, "  skipped: %s\n", r.Spec.Skipped)
		}
		for _, v := range r.Spec.Violations {
			fmt.Fprintf(&b, "  violation %s: %s\n", v.Path, v.Message)
		}
	}

	if r.Fuzz != nil {
		fmt.Fprintf(&b, "\nfuzz: %d request(s) in %dms", r.Fuzz.Requests, r.Fuzz.DurationMS)
		if r.Fuzz.Skipped > 0 {
			fmt.Fprintf(&b, ", %d skipped by max_requests", r.Fuzz.Skipped)
		}
		if r.Fuzz.Aborted != "" {
			fmt.Fprintf(&b, ", aborted: %s", r.Fuzz.Aborted)
		}
		b.WriteString("\n")
		for _, f := range r.Fuzz.Findings {
			fmt.Fprintf(&b, "  [%s] %s %s: %s\n", f.Severity, f.Kind, f.Target, oneLine(f.Evidence))
		}
		for _, f := range r.Fuzz.Advisory {
			fmt.Fprintf(&b, "  [advisory] %s %s: %s\n", f.Kind, f.Target, oneLine(f.Evidence))
		}
	}

	if r.Diff != nil && len(r.Diff.Changes) > 0 {
		fmt.Fprintf(&b, "\ndiff vs %s (%s)\n", r.Diff.BaselineFile, r.Diff.Format)
		for _, c := range r.Diff.Changes {
			fmt.Fprintf(&b, "  %s\n", c.Summary())
		}
	}

	if len(r.Warnings) > 0 {
		b.WriteString("\nwarnings:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  - %s\n", w)
		}
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strx.Truncate(s, 160)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kilhook report — {{.Request.Name}}</title>
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem; font: 15px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; background: #0f1115; color: #e6e6e6; }
main { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 1.35rem; margin: 0 0 .25rem; }
h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: .08em; color: #9aa4b2; margin: 2rem 0 .5rem; }
.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.verdict { display: inline-block; padding: .15rem .55rem; border-radius: 999px; font-size: .8rem; font-weight: 600; }
.ok { background: #10331f; color: #48d18a; }
.ok-text { color: #48d18a; }
.bad { background: #3a1618; color: #ff7b72; }
.card { background: #161a20; border: 1px solid #242a33; border-radius: 10px; padding: 1rem 1.1rem; }
table { width: 100%; border-collapse: collapse; font-size: .9rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #242a33; vertical-align: top; }
th { color: #9aa4b2; font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; }
tr:last-child td { border-bottom: none; }
.sev { font-weight: 700; font-size: .75rem; padding: .1rem .45rem; border-radius: 4px; }
.sev-high { background: #3a1618; color: #ff7b72; }
.sev-medium { background: #3a2a10; color: #f0b429; }
.sev-low { background: #10273a; color: #79c0ff; }
.sev-info { background: #22262e; color: #9aa4b2; }
pre { margin: .35rem 0 0; padding: .7rem .8rem; background: #0b0d11; border: 1px solid #242a33; border-radius: 8px; overflow: auto; max-height: 32rem; white-space: pre-wrap; word-break: break-word; }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; font-size: .9rem; }
.kv dt { color: #9aa4b2; }
.kv dd { margin: 0; }
.muted { color: #9aa4b2; }
footer { margin-top: 2.5rem; color: #6b7280; font-size: .8rem; }
</style>
</head>
<body>
<main>
  <h1>{{.Request.Name}}</h1>
  <p class="muted mono">{{.Request.Method}} {{.Request.URL}}</p>
  {{if eq .ExitCode 0}}<span class="verdict ok">clean</span>{{else if eq .ExitCode 2}}<span class="verdict bad">incomplete</span>{{else}}<span class="verdict bad">problems found</span>{{end}}
  <span class="muted"> · {{.ClassSummary}}</span>

  <h2>Request</h2>
  <section class="card">
    <dl class="kv">
      {{if .Request.File}}<dt>file</dt><dd class="mono">{{.Request.File}}</dd>{{end}}
      <dt>method</dt><dd class="mono">{{.Request.Method}}</dd>
      <dt>url</dt><dd class="mono">{{.Request.URL}}</dd>
      {{if .Request.Headers}}<dt>headers</dt><dd class="mono">{{range $k, $v := .Request.Headers}}{{$k}}: {{$v}}<br>{{end}}</dd>{{end}}
      {{if .Request.Query}}<dt>query</dt><dd class="mono">{{range $k, $v := .Request.Query}}{{$k}}={{$v}}<br>{{end}}</dd>{{end}}
      {{if .Request.BodyPreview}}<dt>body</dt><dd><pre>{{.Request.BodyPreview}}</pre></dd>{{end}}
    </dl>
  </section>

  {{if .Response}}
  <h2>Response</h2>
  <section class="card">
    <dl class="kv">
      <dt>status</dt><dd class="mono">{{.Response.Status}}</dd>
      <dt>duration</dt><dd>{{.Response.DurationMS}} ms</dd>
      <dt>size</dt><dd>{{.Response.SizeBytes}} bytes{{if .Response.Truncated}} (truncated){{end}}</dd>
      {{if .Response.ContentType}}<dt>content-type</dt><dd class="mono">{{.Response.ContentType}}</dd>{{end}}
    </dl>
    {{if .Response.BodyPreview}}<pre>{{.Response.BodyPreview}}</pre>{{end}}
  </section>
  {{end}}

  {{if .Spec}}
  <h2>Contract</h2>
  <section class="card">
    <dl class="kv">
      <dt>operation</dt><dd class="mono">{{.Spec.Operation}}</dd>
      {{if .Spec.StatusKey}}<dt>status rule</dt><dd class="mono">{{.Spec.StatusKey}}</dd>{{end}}
      {{if .Spec.MediaType}}<dt>media type</dt><dd class="mono">{{.Spec.MediaType}}</dd>{{end}}
    </dl>
    {{if .Spec.Skipped}}<p class="muted">skipped: {{.Spec.Skipped}}</p>{{end}}
    {{if .Spec.Violations}}
    <table>
      <thead><tr><th>path</th><th>problem</th></tr></thead>
      <tbody>
      {{range .Spec.Violations}}<tr><td class="mono">{{.Path}}</td><td>{{.Message}}</td></tr>{{end}}
      </tbody>
    </table>
    {{else if not .Spec.Skipped}}<p class="ok-text">response matches the contract</p>{{end}}
  </section>
  {{end}}

  {{if .Fuzz}}
  <h2>Fuzzing</h2>
  <section class="card">
    <dl class="kv">
      <dt>requests</dt><dd>{{.Fuzz.Requests}}{{if .Fuzz.Skipped}} ({{.Fuzz.Skipped}} skipped by max_requests){{end}}</dd>
      <dt>duration</dt><dd>{{.Fuzz.DurationMS}} ms</dd>
      {{if .Fuzz.RateLimit}}<dt>rate limit</dt><dd>{{.Fuzz.RateLimit}} req/s</dd>{{end}}
      {{if .Fuzz.Targets}}<dt>targets</dt><dd class="mono">{{range .Fuzz.Targets}}{{.}} {{end}}</dd>{{end}}
      {{if .Fuzz.Methods}}<dt>methods</dt><dd class="mono">{{range .Fuzz.Methods}}{{.}} {{end}}</dd>{{end}}
      {{if .Fuzz.Aborted}}<dt>aborted</dt><dd>{{.Fuzz.Aborted}}</dd>{{end}}
    </dl>
    {{if .Fuzz.Findings}}
    <table>
      <thead><tr><th>severity</th><th>kind</th><th>target</th><th>evidence</th></tr></thead>
      <tbody>
      {{range .Fuzz.Findings}}
      <tr>
        <td><span class="sev sev-{{.Severity}}">{{.Severity}}</span></td>
        <td class="mono">{{.Kind}}{{if gt .Count 1}} ×{{.Count}}{{end}}</td>
        <td class="mono">{{.Target}}</td>
        <td><span class="mono">{{.Payload}}</span><br><span class="muted">{{.Evidence}}</span></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="muted">no findings</p>{{end}}
    {{if .Fuzz.Advisory}}
    <p class="muted">advisory observations (not findings)</p>
    <table>
      <thead><tr><th>kind</th><th>target</th><th>note</th></tr></thead>
      <tbody>
      {{range .Fuzz.Advisory}}<tr><td class="mono">{{.Kind}}</td><td class="mono">{{.Target}}</td><td class="muted">{{.Evidence}}</td></tr>{{end}}
      </tbody>
    </table>
    {{end}}
  </section>
  {{end}}

  {{if .Diff}}
  <h2>Diff</h2>
  <section class="card">
    <p class="muted">baseline: <span class="mono">{{.Diff.BaselineFile}}</span> ({{.Diff.Format}})</p>
    {{if .Diff.Changes}}
    <table>
      <thead><tr><th>path</th><th>change</th><th>before</th><th>after</th></tr></thead>
      <tbody>
      {{range .Diff.Changes}}<tr><td class="mono">{{.Path}}</td><td>{{.Kind}}</td><td class="mono">{{.Before}}</td><td class="mono">{{.After}}</td></tr>{{end}}
      </tbody>
    </table>
    {{else}}<p class="muted">no differences from baseline</p>{{end}}
  </section>
  {{end}}

  {{if .Warnings}}
  <h2>Warnings</h2>
  <section class="card"><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul></section>
  {{end}}

  <footer>kilhook {{.Version}} · generated {{.Generated.Format "2006-01-02 15:04:05 UTC"}} · local run, no data left this machine</footer>
</main>
</body>
</html>
`
