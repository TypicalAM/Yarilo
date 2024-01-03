# SniffSniff

## Build

### Requirements

- `cmake`
- `libtins`
- `ninja`
- `boost` (for logging)

### Download

```
git clone https://github.com/TypicalAM/SniffSniff
cd SniffSniff/backend
git-crypt unlock ../../key # if you want to have access to our own pcap files
```

### Build

```
cmake -G Ninja -B build .
ninja -C build
./sniffsniff
```
