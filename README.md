# Terraform Provider Keepass

The Keepass provider is used to read secrets from a keepass database file.

## Build provider

Run the following command to build the provider

```shell
$ go build -o terraform-provider-keepass
```

## Local release build

```shell
$ go install github.com/goreleaser/goreleaser@latest
```

```shell
$ make release
```

You will find the releases in the `/dist` directory. You will need to rename the provider binary to `terraform-provider-keepass` and move the binary into the appropriate subdirectory within the user plugins directory.

## Test sample configuration

First, build and install the provider.

```shell
$ make install
```

Then, navigate to the `examples` directory. 

```shell
$ cd examples
```

Run the following command to initialize the workspace and apply the sample configuration.

```shell
$ terraform init && terraform apply
```

## Run tests
```shell
$ make test
```