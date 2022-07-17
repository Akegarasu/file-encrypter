# file-encrypter

## About

using go stand library cipher.Stream support large file encrypt/decrypt

## Usage

### encrypt

```shell
file-encrypter e -k key -i inputfile -o outputfile
```

### decrypt

```shell
file-encrypter d -k key -i inputfile -o outputfile
```

### compare sha256

```shell
file-encrypter sha file1 file2
```