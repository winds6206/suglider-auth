# How to Use

## make command

### make build

Use `make build` to compile the binary file with golang codes, that will generate a diretory named "bin" and binary file will put inside the diretory.

> Enviroment variable `VERSION` can change by yourself

```bash
make build VERSION=1.0.0
```

Go to "bin" diretory and use `go run` command to run the http server.

> Config(.toml) in the `./configs/configuration/` is just example, that can be copy to any where you want to place. Make sure use the flag `-c` to specify config(.toml) path.

```bash
cd ./bin

ENV=dev go run suglider-auth -c ~/tmp/dev.toml
```

we can use `make clean` to clean the binary file in the "bin" directory.
```bash
make clean
```

### make docker

Command `make docker` can build docker images

```bash
make docker VERSION=1.0.0
```

## Compile and run the main.go

Compile and run the program through main.go

```bash
ENV=dev go run main.go -c ~/tmp/dev.toml
```

## Test

### Unit Test

Run the following command to start unit test for entire project:

```bash
make test
```

You could clean test cache by the following command:

```bash
make clean
```
