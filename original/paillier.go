package paillier

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)
var ErrLargeMessage = errors.New("message size must be smaller than Paillier public key size")
var ErrLargeCipher = errors.New("cipher size must be smaller Paillier public key size")

// PrivateKey represents a Paillier private key.
type PrivateKey struct {
	PublicKey
	L *big.Int // phi(n), (p-1)*(q-1)
	U *big.Int // l^-1 mod n
}

// PublicKey represents Paillier public key.
type PublicKey struct {
	N        *big.Int // modulus
	G        *big.Int // n+1, since p and q are same length
	NSquared *big.Int // N^2
}

// GenerateKey generates the Paillier private key according to the given bit size.
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	// prime number p
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// prime number q
	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// n = p * q
	n := new(big.Int).Mul(p, q)
	// g = n + 1
	g := new(big.Int).Add(n, one)
	// nsquare = n * n
	nsquare := new(big.Int).Mul(n, n)

	// l = phi(n) = (p-1) * (q-1)
	l := new(big.Int).Mul(
		new(big.Int).Sub(p, one),
		new(big.Int).Sub(q, one),
	)
	// l^(-1) mod n
	u := new(big.Int).ModInverse(l, n)

	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: nsquare,
			G:        g,
		},
		L: l,
		U: u,
	}, nil
}

// Encrypt encrypts a plain text represented as a byte array. It returns
// an error if the plain text value is larger than the modulus N^2 of the Public key.
func (pub *PublicKey) Encrypt(plainText []byte) ([]byte, error) {
	r, err := rand.Prime(rand.Reader, pub.N.BitLen())
	if err != nil {
		return nil, err
	}

	m := new(big.Int).SetBytes(plainText)
	if m.Cmp(pub.NSquared) == 1 { //  m < N^2
		return nil, ErrLargeMessage
	}

	// c = g^m * r^n mod n^2
	n := pub.N
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(pub.G, m, pub.NSquared),
			new(big.Int).Exp(r, n, pub.NSquared),
		),
		pub.NSquared,
	)
	return c.Bytes(), nil
}

// Decrypt decrypts the passed cipher text. It returns
// an error if the cipher text value is larger than the modulus N^2 of Public key.
func (priv *PrivateKey) Decrypt(cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)
	if c.Cmp(priv.NSquared) == 1 { // c < n^2
		return nil, ErrLargeCipher
	}

	// c^l mod n^2
	a := new(big.Int).Exp(c, priv.L, priv.NSquared)

	// let L(a) = l(a) and should not confuse it with 'priv.L'.
	// So, l(a) = (a - 1) / n
	l := new(big.Int).Div(
		new(big.Int).Sub(a, one),
		priv.N,
	)

	// m = L(c^l mod n^2) * u mod n
	m := new(big.Int).Mod(
		new(big.Int).Mul(l, priv.U),
		priv.N,
	)
	return m.Bytes(), nil
}

// HomomorphicEncTwo performs homomorphic operation over two chiphers.
// Paillier has additive homomorphic property, so the resultant cipher
// contains the sum of two numbers.
func (pub *PublicKey) HomomorphicEncTwo(c1, c2 []byte) ([]byte, error) {
	cipherA := new(big.Int).SetBytes(c1)
	cipherB := new(big.Int).SetBytes(c2)
	if cipherA.Cmp(pub.NSquared) == 1 && cipherB.Cmp(pub.NSquared) == 1 { // (c1 & c2) < N^2
		return nil, ErrLargeCipher
	}

	// C = c1*c2 mod N^2
	C := new(big.Int).Mod(
		new(big.Int).Mul(cipherA, cipherB),
		pub.NSquared,
	)
	return C.Bytes(), nil
}

// HommorphicEncMultiple performs homomorphic operation over two chiphers.
// Paillier has additive homomorphic property, so the resultant cipher
// contains the sum of multiple numbers.
func (pub *PublicKey) HommorphicEncMultiple(ciphers ...[]byte) ([]byte, error) {
	C := one

	for i := 0; i < len(ciphers); i++ {
		cipher := new(big.Int).SetBytes(ciphers[i])
		if cipher.Cmp(pub.NSquared) == 1 { //  C < N^2
			return nil, ErrLargeCipher
		}
		// C = c1*c2*c3...cn mod N
		C = new(big.Int).Mod(
			new(big.Int).Mul(C, cipher),
			pub.NSquared,
		)
	}
	return C.Bytes(), nil
}
