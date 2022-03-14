package paillier

import (
	"crypto/rand"
	"io"
	"math/big"
)

var one = big.NewInt(1)

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
