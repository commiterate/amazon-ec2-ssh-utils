# Tests

Client tests.

## Layout

See [Organizing a Go module](https://go.dev/doc/modules/layout).

```text
Key:
🤖 = Generated

.
│   # Build outputs.
├── build 🤖
│   └── ...
│
│   # Go internal packages.
├── internal
│   └── ...
│
│   # Go configuration.
├── go.mod
├── go.sum 🤖
│
│   # Build recipes.
└── justfile
```

## Developing

Common build recipes are provided as Just recipes. To list them, run:

```shell
just help
```

To build the project, run:

```shell
just release
```

To run the tests, run:

```shell
go test ./internal/...
```
