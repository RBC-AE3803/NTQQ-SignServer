# Linux NTQQ SignServer

本项目只能在 Linux 上使用。
本项目基于nimeng1299/SignServer项目二开
## 如何使用？

首先，前往官网下载 QQ。

推荐下载 Linux x64 3.2.19-39038 版本。如果您需要下载其他版本，则需要修改 `src/main.rs` 文件。

然后解压或安装 QQ。

接着：

```sh
gcc -std=c99 -shared -fPIC -o libsymbols.so symbols.c
cargo build --release
```

将 `libsymbols.so` 和 `target/release/sign` 文件 和 static 文件夹 放到包含 `wrapper.node` 文件的文件夹(通常是/opt/QQ/resources/app)中。

切换目录到包含 `wrapper.node` 的文件夹，然后运行 `./sign`。

服务器将监听 0.0.0.0:11478。如果您想监听其他端口，请修改 `src/main.rs` 文件。

尽情使用吧！
