# **An example to show how to use libbpf for bpf relocate**

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
[![Build and publish](https://github.com/eunomia-bpf/libbpf-starter-template/actions/workflows/publish.yml/badge.svg)](https://github.com/eunomia-bpf/libbpf-starter-template/actions/workflows/publish.yml)
![GitHub stars](https://img.shields.io/github/stars/eunomia-bpf/libbpf-starter-template?style=social)

An example to show how to use libbpf for bpf relocate. 

For other related examples, please refer to [Expanding eBPF Compile Once, Run Everywhere(CO-RE) to Userspace Compatibility](https://eunomia.dev/tutorials/38-btf-uprobe/)

## **How to use**

### **Clone your new repository**

Clone your newly created repository to your local machine:

```sh
git clone https://github.com/your_username/your_new_repository.git --recursive
```

Or after clone the repo, you can update the git submodule with following commands:

```sh
git submodule update --init --recursive
```

### **Install dependencies**

For dependencies, it varies from distribution to distribution. You can refer to shell.nix and dockerfile for installation.

On Ubuntu, you may run `make install` or

```sh
sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm
```

to install dependencies.

### **Build the project**

To build the project, run the following command:

```sh
make build
```

This will compile your code and create the necessary binaries. You can you the `Github Code space` or `Github Action` to build the project as well.

### ***Run the Project***

You can run the binary with:

```console
sudo src/relo
```

### **7. GitHub Actions**

This template also includes a GitHub action that will automatically build and publish your project when you push to the repository.
To customize this action, edit the **`.github/workflows/publish.yml`** file.

## **Contributing**

We welcome contributions to improve this template! If you have any ideas or suggestions,
feel free to create an issue or submit a pull request.

## **License**

This project is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.
