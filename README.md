# SniffSniff

## Build

### Requirements

- `cmake`
- `libpcap`
- `ninja`

Download the latest release of [pcapplusplus](https://pcapplusplus.github.io/) and put it in the root directory as `pcapplusplus`. Then run

```
mkdir build
cmake -DPcapPlusPlus_ROOT=$PWD/pcapplusplus -G Ninja -B build .
ninja -C build
./sniffsniff
```

If you also want lsp completion do (`clangd`)

```
cp build/compile_commands.json .
```
