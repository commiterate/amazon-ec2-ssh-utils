# Infrastructure

AWS infrastructure for client tests.

## Layout

```text
Key:
🤖 = Generated

.
│   # Build outputs.
├── build 🤖
│   └── ...
│
│   # AWS CDK source.
├── src
│   └── ...
│
│   # Bun configuration.
├── bunfig.toml
├── package.json
├── bun.lock 🤖
│
│   # AWS CDK configuration.
├── cdk.json
├── cdk.context.json 🤖
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
