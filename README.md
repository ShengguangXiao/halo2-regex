# halo2-regex

**Regex verification circuit application based on halo2.**

## Disclaimer
DO NOT USE THIS LIBRARY IN PRODUCTION. At this point, this is under development not audited. It has known and unknown bugs and security flaws.

## Features
`halo2-regex` provides a application for a regex verification chip compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).

## Requirement
- rustc 1.68.0-nightly (0468a00ae 2022-12-17)
- cargo 1.68.0-nightly (cc0a32087 2022-12-14)

## Installation and Build
You can install and build our library with the following commands.
```bash
git clone https://github.com/zkemail/halo2-regex.git
cd halo2-regex
cargo build --release
```
## Build
You can open the API specification by executing `cargo build --release`.

## Usage
Check How to use the application. `./target/release/halo2-regex --help`.

## Test
You can run the tests by executing `cargo test --release`.

## Examples

### Generate lookup file and substr files

```bash
./target/release/halo2-regex gen-halo2-texts --decomposed-regex-path=./test_regexes/regex3_test.json --allstr-file-path=./test_regexes/regex3_test_lookup.txt --substrs-dir-path=./test_regexes/
```

### Generate parameters
```
./target/release/halo2-regex gen-params --k 17
```

### Generate prove and verify keys
```
./target/release/halo2-regex gen-keys --allstr-file-path=./test_regexes/regex3_test_lookup.txt --substr-file-path=./test_regexes/substr3_test_lookup.txt
```

### Generate valid regex proof
```
./target/release/halo2-regex prove --allstr-file-path=./test_regexes/regex3_test_lookup.txt --substr-file-path=./test_regexes/substr3_test_lookup.txt --string-to-verify="dummy\r\nfrom:alice<alice@gmail.com>\r\n" --target-pos=18 --target-string="alice@gmail.com" --is-success
```

### Verify valid proof
With the above proof result, the command should print `proof is valid`
```
./target/release/halo2-regex verify --allstr-file-path=./test_regexes/regex3_test_lookup.txt --substr-file-path=./test_regexes/substr3_test_lookup.txt
```

### Generate invalid regex proof
```
./target/release/halo2-regex prove --allstr-file-path=./test_regexes/regex3_test_lookup.txt --substr-file-path=./test_regexes/substr3_test_lookup.txt --string-to-verify="dummy from:alice<alice@gmail.com>" --target-pos=18 --target-string="alice@gmail.com"
```

### Verify invalid proof
With the above proof result, the command should print `proof is invalid`
```
./target/release/halo2-regex verify --allstr-file-path=./test_regexes/regex3_test_lookup.txt --substr-file-path=./test_regexes/substr3_test_lookup.txt
```
