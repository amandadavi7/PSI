# Private Set Intersection (PSI)

### Faster Unbalanced Private Set Intersection

By *Amanda Resende and Diego Aranha* in Financial Cryptography and Data Security 2018 (FC 2018) [2] and to be published in the Journal of Cryptographic Engineering (JCEN) [2]. Please note that the code is currently being restructured and not all routines might work correctly. The implementation of OT-based PSI protocol [6], the naive hashing, the server-aided protocol [3] and the Diffie-Hellman-based PSI protocol [4] was obtained from Pinkas et al. [6] available at https://github.com/encryptogroup/PSI, with some changes. The PSI code is licensed under AGPLv3, see the LICENSE file for a copy of the license. 

### Features
---

* An implementation of different PSI protocols: 
  * the naive hashing solutions where elements are hashed and compared 
  * the server-aided protocol of [3]
  * the Diffie-Hellman-based PSI protocol of [4]
  * the Diffie-Hellman-based PSI protocol of [5]
  * the OT-based PSI protocol of [6]
  * the unbalanced PSI protocol based on public key cryptography [1,2] 

This code is provided as a experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

WARNING: Because of the change in the elliptic curve, the OT-based PSI protocol of [6] is not working. For correct execution see https://github.com/encryptogroup/PSI.

### Requirements
---

* A **Linux distribution** of your choice (the code was developed and tested with recent versions of [Ubuntu](http://www.ubuntu.com/)).
* **Required packages:**
  * [`g++`](https://packages.debian.org/testing/g++)
  * [`make`](https://packages.debian.org/testing/make)
  * [`libgmp-dev`](https://packages.debian.org/testing/libgmp-dev)
  * [`libglib2.0-dev`](https://packages.debian.org/testing/libglib2.0-dev)
  * [`libssl-dev`](https://packages.debian.org/testing/libssl-dev)

  Install these packages with your favorite package manager, e.g, `sudo apt-get install <package-name>`.

### Building the Project

1. Clone a copy of the main git repository and its submodules by running:

	```
	git clone --recursive git://github.com/amandadavi7/PSI
	```

2. Enter the Framework directory: `cd PSI/`

3. Select the macro #define BASIC_PROTOCOLS in src/util/helpers

4. Call `make` in the root directory to compile all dependencies, tests, and examples and create the executables: **psi.exe** (used for benchmarking) and **demo.exe** (a small demonstrator for intersecting numbers).

Please note that downloading this project as ZIP file will yield compilation errors, since the Miracl library is included as external project. To solve this, download the Miracl sources in commit version `cff161b` (found [here](https://github.com/CertiVox/Miracl/tree/cff161bad6364548b361b63938a988db23f60c2a) and extract the contents of the main folder in `src/externals/Miracl`. Then, continue with steps 2 and 3.

### Executing the Code

An example demo is included and can be run by opening two terminals in the root directory. Execute in the first terminal:

	./demo.exe -r 0 -p 0 -f sample_sets/sample_alice
	
and in the second terminal:
	
	./demo.exe -r 1 -p 0 -f sample_sets/sample_bob

These commands will run the naive hashing protocol and compute the intersection on the 1024 randomly generated numbers in sample_sets/sample_alice and sample_sets/sample_bob (where 5 intersecting elements were altered). To use a different protocol, the ['-p'] option can be varied as follows:	

  * `-p 0`: the naive hashing protocol 
  * `-p 1`: the server-aided protocol of [3]
  * `-p 2`: the Diffie-Hellman-based PSI protocol of [4]
  * `-p 3`: the Diffie-Hellman-based PSI protocol of [5]
  * `-p 4`: Cuckoo filter [7]
  * `-p 5`: Rank-and-Select-based Quotient filter (RSQF) [8]
  * `-p 6`: the OT-based PSI protocol of [6]

For the next ['-p'] option must be use different commands. For executing the Diffie-Hellman-based PSI protocol of [5] and unbalanced PSI protocol based on public key cryptography [1,2], it must executing the preprocessing phase at least once.

For`-p 3` (Preprocessing): generating a database and send to the client in the the Diffie-Hellman-based PSI protocol of [5]. It must be selected only the macro #define PREPROCESSING in src/util/helpers, call `make` and opening two terminals in the root directory. Execute in the first terminal:

	./demo.exe -r 0 -p 3 -f sample_sets/sample_alice

and in the second terminal:

	./demo.exe -r 1 -p 3 

For `-p 3`: executing the the Diffie-Hellman-based PSI protocol of [5]. It must be selected only the macro #define OPTIMIZED_PROTOCOLS, call `make` and opening two terminals in the root directory. Execute in the first terminal:

	./demo.exe -r 0 -p 3 -n number_of_elements_in_database

and in the second terminal:

	./demo.exe -r 1 -p 3 -f sample_sets/sample_bob

For `-p 4` (Preprocessing): generating and sending a Cuckoo filter [7] to the client in the unbalanced PSI protocol based on public key cryptography [1,2]. It must be selected only the macro #define PREPROCESSING in src/util/helpers, call `make` and opening two terminals in the root directory. Execute in the first terminal:

	./demo.exe -r 0 -p 4 -f sample_sets/sample_alice

and in the second terminal:

	./demo.exe -r 1 -p 4 

For `-p 5` (Preprocessing): generating and sending a a RSQF [8] to the client in the unbalanced PSI protocol based on public key cryptography [1,2]. It must be selected only the macros #define PREPROCESSING, #define NEW_KEY and #define GENERATE_AND_SEND in src/util/helpers, call `make` and opening two terminals in the root directory. Execute in the first terminal:

	./demo.exe -r 0 -p 5 -f sample_sets/sample_alice

and in the second terminal:

	./demo.exe -r 1 -p 5 

For `-p 6`: executing the unbalanced PSI protocol based on public key cryptography [1]. It must be selected only the macro #define OPTIMIZED_PROTOCOLS (#define CUCKOO_FILTER must be selected to use the Cuckoo filter), call `make` and opening two terminals in the root directory. Execute in the first terminal:

	./demo.exe -r 0 -p 6 -n number_of_elements_in_filter

and in the second terminal:

	./demo.exe -r 1 -p 6 -f sample_sets/sample_bob


This should print the following output in the second terminal: 

`	Computation finished. Found 5 intersecting elements:`
`	1521395961					    `
`	2049284277					    `
`	2109400902					    `
`	2048270713					    `
`	0362147482					    `

For further information about the program options, run ```./demo.exe -h```.

### Generating Random Email Adresses

Further random numbers can be generated by navigating to `sample_sets/` and invoking: 

```
	python3 emailgenerator.py and after enter with the amount of number to be generate and the name of the file to save those numbers.
```

### References

[1] A. Resende and D. Aranha. Faster Unbalanced Private Set Intersection. In Financial Cryptography and Data Security (FC), LNCS. Springer, 2018.

[2] A. Resende and D. Aranha. Faster Unbalanced Private Set Intersection in the Semi-Honest Setting. To be published in the Journal of Cryptographic Engineering (JCEN).

[3] S. Kamara, P. Mohassel, M. Raykova, and S. Sadeghian. Scaling private set intersection to billion-element sets. In Financial Cryptography and Data Security (FC), LNCS. Springer, 2014.

[4] C. Meadows. A more efficient cryptographic matchmaking protocol for use in the absence of a continuously available third party. In IEEE S&P’86, pages 134–137. IEEE, 1986.

[5] P. Baldi, R. Baronio, E. D. Cristofaro, P. Gasti, and G. Tsudik, Countering GATTACA: Efficient and Secure Testing of Fully-sequenced Human Genomes. In ACM Conference on Computer and Communications Security, pp. 691–702, 2011.

[6] B. Pinkas, T. Schneider, M. Zohner. Scalable Private Set Intersection Based on OT Extension. In ACM Transactions on Privacy and Security, pages 7:1–7:35, 2018. 

[7] B. Fan, D. G. Andersen, M. Kaminsky, M. Mitzenmacher. Cuckoo Filter: Practically Better Than Bloom. In ACM International on Conference on Emerging Networking Experiments and Technologies (CoNEXT), pages 75–88, 2014. 

[8] P. Pandey, M.A. Bender, R. Johnson, R. Patro. A General-Purpose Counting Filter: Making Every Bit Count. In ACM International Conference on Management of Data (SIGMOD),  pages 775–787, 2017.
