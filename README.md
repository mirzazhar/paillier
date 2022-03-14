# Paillier Cryptosystem
 This package is inspired by https://github.com/Roasbeef/go-go-gadget-paillier.
 Furthermore, this package is designed according to the cryptographic primitives and pseudo-codes of the original version of the Paillier cryptosystem. Simply, it covers the implementation of the following algorithms.
 - Key Generation
 - Encryption
 - Decryption

Paillier has [additive homomorphic encryption property](https://dl.acm.org/doi/pdf/10.1145/3214303), and its type is Partially Homomorphic Encryption (PHE). Therefore, this clarifies that the multiplication of ciphers results in the sum of original numbers.

Moreover, In this package, the realized additive homomorphic property is implemented into the following PHE functions:
- Homomorphic Encryption over two ciphers
- Homomorphic Encryption over multiple ciphers

## Installation
```sh
go get -u github.com/mirzazhar/paillier
```
## Warning
This package is designed with a keen focus for research and education purposes. Of course, it may contain bugs and needs several improvements. Therefore, this package should not be used for production purposes.
## Usage & Examples
## LICENSE
MIT License
## References
1. https://en.wikipedia.org/wiki/Paillier_cryptosystem
2. https://github.com/Roasbeef/go-go-gadget-paillier
3. https://dl.acm.org/doi/pdf/10.1145/3214303
