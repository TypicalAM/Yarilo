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
cd SniffSniff
git-crypt unlock ../key # if you want to have access to our own
```

### Build (in root dir)

```
cmake -G Ninja -B build .
ninja -C build
./sniffsniff
```
