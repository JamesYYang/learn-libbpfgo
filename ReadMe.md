# try to learn libbpfgo

## Install packages on Ubuntu 22.04

```sh
sudo apt-get update
sudo apt-get install golang-go
sudo apt-get install libbpf-dev make clang llvm libelf-dev
sudo apt-get install --yes linux-tools-5.15.0-39-generic
```

## Run

```sh
make
./hello-world
```