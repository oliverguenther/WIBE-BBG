#Boneh–Boyen–Goh Wildcarded Identity-Based Encryption (WIBE-BBG)

WIBE-BBG is an implementation of the Boneh–Boyen–Goh Wildcarded Identity-Based Encryption Scheme [1, Sec. 5.2].

WIBE-BBG depends on the [Pairing-Based Cryptography Library](http://crypto.stanford.edu/pbc/) by Ben Lynn.

<!--The scheme depends on a symmetric pairing, thus a [Type-A pairing](http://crypto.stanford.edu/pbc/manual/ch08s03.html) is required.-->

**[1]** Michel Abdalla et. al. - *Wildcarded Identity-Based Encryption*. Journal of Cryptology: Volume 24, Issue 1 , pp 42-82.
http://link.springer.com/article/10.1007%2Fs00145-010-9060-3

## Installation

WIBE-BBG depends on the PBC library, which itself depends on GMP. Please see their respective manuals for build instructions.

To build and execute the test program, simply run:

	make && make test

## Contact
Oliver Günther, oliver.guenther@cs.tu-darmstadt.de

##LICENSE

WIBE-BBG is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

WIBE-BBG is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
