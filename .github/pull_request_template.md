## What and why

<!-- One or two sentences. Reference requirement IDs, e.g. LW-FR-04, and issues: Closes #123 -->

## How it was tested

- [ ] `go test -race ./...`
- [ ] `go vet ./...` and `golangci-lint run`
- [ ] Golden files updated and reviewed (if output changed)

## Security checklist

- [ ] Does not execute, import or launch scanned content
- [ ] No new network access in default code paths
- [ ] No env/header/secret values in any output
- [ ] New dependencies justified (or none added)
- [ ] Commits signed off (`git commit -s`)
