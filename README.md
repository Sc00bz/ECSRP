ECSRP
=====
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
An eavesdropper, malicious server, or malicious client can't obtain anything to be able to authenticate or crack the password. After obtaining the server's data, one can authenticate to/from a client and attempt to crack the password, but not authenticate to/from the server.

## TODO
* Use the fast formulas for scalar, (partial) point multiplication for Curve25519
* Better functions for scalar, (full) point multiplication for Curve25519
* Curve41417
* Rewrite in C++
* Get code production ready (ie not PoC code [piece of crap code])

## P and Q
For Curve25519, P is (9, ...) and Q is (16, ...).

## I would like to hear from you
* If you broke this
* If you have an attack on this that is not mentioned above
* Something is incorrect

## Thanks
* Steven Alexander
* Michael Hamburg

## License
This code is distributed under the terms of the GNU General Public License 2.
