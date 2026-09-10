# ingestor

## Supported Go version

**Go 1.22.7** — this is the supported and tested version for this branch.

Verified with the official `golang:1.22.7` Docker image and `GOTOOLCHAIN=local`:

- `CGO_ENABLED=0 go build` succeeds
- `go test ./...` passes (all packages)

### Notes

The dependency versions are pinned to releases that still support Go 1.22:

- `github.com/golang-jwt/jwt/v5` `v5.2.1`
- `github.com/joho/godotenv` `v1.5.1`
- `golang.org/x/crypto` `v0.31.0`
- `modernc.org/sqlite` `v1.34.4`

Newer releases of `golang.org/x/crypto` (and the `modernc.org` stack) require a newer
Go toolchain and will not build with `GOTOOLCHAIN=local` on this version.

### Test build

```sh
docker run --rm -v "$PWD:/src" -w /src -e GOTOOLCHAIN=local golang:1.22.7 \
  sh -c 'CGO_ENABLED=0 go build -o /ingestor . && go test ./...'
```
