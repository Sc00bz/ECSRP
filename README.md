ECSRP
=====
## Just use SPAKE2-EE
I found out about SPAKE2-EE after coming up with this because I was told there isn't a good elliptic curve SPR. SPAKE2-EE was made by smart people and they have security proofs for SPAKE2-EE.

## Description
* P and Q are points on the curve in the same cyclical group (ie aP = Q for some unknown a)
* k is the key derived from the password
* 1/k is done by modular inverse for the cyclical group size
* Server has (1/k)P and (1/k)Q
* a and b are random private keys
* X(P) returns the x coordinate of a point
* || is concatenation
```
C->S: Identity
C<-S: b(1/k)P + (1/k)Q, salt, password KDF settings
C:    k(b(1/k)P + (1/k)Q) - Q = bP
C->S: X(aP), H(X(bP) || X(abP))
S:    Verify
C<-S: H(X(aP) || X(bP) || X(abP))
C:    Verify
```

Note the client needs to check "b(1/k)P + (1/k)Q" is on the curve and in the same cyclical group as P and Q.

## Attacks
An eavesdropper, malicious server, or malicious client can't obtain anything to be able to authenticate or crack the password. After obtaining the server's data, one can authenticate to/from a client and attempt to crack the password, but not authenticate to/from the server. Given the data stored on the server one can make password guesses. Since the salt is public one can build a list of password guesses. Once the server data becomes available, the list can be used to near instantly check if any guess was correct.

## TODO
* Use the fast formulas for scalar, (partial) point multiplication for Curve25519
* Better functions for scalar, (full) point multiplication for Curve25519
* Curve41417
* Rewrite in C++
* Get code production ready (ie not PoC code [piece of crap code])

## P and Q
For Curve25519, P is (9, 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9) and Q is (16, 0x36b20194b9ee7885e888642d2006d60cdcc836d17f615e8416989556b3941598).

## I would like to hear from you
* If you broke this
* If you have an attack on this that is not mentioned above
* Something is incorrect

## Thanks
* Steven Alexander
* Michael Hamburg

## License
This code is distributed under the terms of the GNU General Public License 2.
