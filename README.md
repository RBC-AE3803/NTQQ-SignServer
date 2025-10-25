# Linux NTQQ SignServer

This project can only be used on Linux.
This project is a secondary development based on the nimeng1299/SignServer project.
## How to use?

First, go to the official website to download QQ.

It is recommended to download the Linux x64 3.2.19-39038 version. If you need to download other versions, you will need to modify the `src/main.rs` file.

Then unzip or install QQ.

And then:

```sh
gcc -std=c99 -shared -fPIC -o libsymbols.so symbols.c
cargo build --release
```

Place the `libsymbols.so` and `target/release/sign` files into the folder that contains the `wrapper.node` file (usually `/opt/QQ/resources/app`).

Switch the directory to the folder containing `wrapper.node`, and then run `./sign`.

The server will listen on `0.0.0.0:11478`. If you want to listen on other ports, please modify the `src/main.rs` file.

Enjoy!