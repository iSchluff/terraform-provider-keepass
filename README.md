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

## License
Copyright 2024 Anton Schubert

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this project except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
