# Beta testing kilhook

The local gate already proves the tests pass. This checklist is for the other
question: is the loop actually better than running one tool to author a request,
another to fuzz it and a third to check the contract?

Budget about 30 minutes. Use an API you are allowed to test.

## Setup

1. Download the v0.1.0 release for Windows, or build from source (see the README).
2. The binaries are unsigned, so SmartScreen will warn: **More info** then
   **Run anyway**.
3. Point the workspace box at a folder of `.kh` files. `testdata/requests` has two
   to start with.

## What to try

Do these in order. Note anything that takes more than a minute or makes you read
the docs twice.

1. **Cold open to first request.** Start the app, pick a workspace, press Run on
   `petstore-get.kh`. Time it. The target is under 60 seconds.
2. **Edit and save.** Open the editor, change the name, press Ctrl+S. Confirm the
   file changed on disk and the sidebar label updated.
3. **Environment.** Add `.kilhook/env/dev.yaml` with a `base_url`, select `dev`,
   run. Confirm the URL in the report resolved.
4. **Fuzz a local API.** Point a `.kh` at `http://localhost:...` with a
   `fuzz.targets` entry you know is reachable. Run. Check that the findings make
   sense and the request count matches what you expected.
5. **Contract check.** Attach a spec to a request that returns a known-good
   response. Confirm it says the response matches, then break one field and
   confirm the violation points at the right path.
6. **Baseline diff.** Run once with **Update baseline**, change the response, run
   again. Confirm only the changed field shows.
7. **Export.** Save the HTML report and open it in a browser. It should be
   self-contained and readable.
8. **CLI.** Run `kh-cli run <file> --json` and check the exit code matches the
   report: `0` clean, `1` findings or violations, `2` incomplete.

## What to report

Open a **beta-feedback** issue with:

- the `.kh` file and spec, with credentials removed
- the report JSON or the exported HTML
- Windows version and the version shown in the title bar
- what you expected and what happened

For friction rather than a bug, say which step above was slow or confusing and
what you expected instead.

## Safety

- Fuzzing a host that is not localhost is skipped unless you confirm it. Do not
  confirm against a system you do not own.
- POST, PUT, PATCH and DELETE fuzzing asks for a typed confirmation because it can
  change data. Use a test environment.
- The bundled payloads are non-destructive, meaning they contain no DROP, DELETE
  or rm. They still exercise the endpoint.

## What we are looking for

- Cold open to first request: is it really under a minute?
- A fuzz finding you can dismiss as noise.
- A step where you had to open the docs to finish it.
- Anything that made you switch back to Postman, Bruno or curl.
