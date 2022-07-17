# file-encrypter

## About

aes-cfb encrypt using go stand library cipher.Stream support large file encrypt/decrypt with low memory cost. 

The key which you have inputted will be calculated with **sha256** (32 byte) for real aes key, so you can use any length keys freely.

iv is **random** which length equals to `aes.BlockSize` and will put to the **encrypted file head**

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
file-encrypter sha file1 file2 ...
```