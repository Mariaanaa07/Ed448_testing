# Ed448_testing
Testing crypto algorithm Ed448
Project Overview This project focuses on the research and automated testing of the Ed448 (Edwards-curve Digital Signature Algorithm), based on the Edwards448 elliptic curve. It was developed as part of a software testing course in the field of cybersecurity to demonstrate modern CI/CD practices and cryptographic verification.

Key Features Correctness Testing: Verification of key generation, signing, and signature verification processes according to the RFC 8032 standard.

Performance Benchmarking: Comparative speed analysis between the cryptography and pycryptodome libraries for the Ed448 algorithm.

Automated CI/CD: Configured GitHub Actions workflows to automatically trigger tests on every code update (Push/Pull Request).

Static Application Security Testing (SAST): Integrated security scanning using Bandit to identify potential vulnerabilities in the Python code.

Tech Stack Programming Language: Python 3.13

Cryptographic Libraries: cryptography, pycryptodome

Testing Frameworks: pytest, pytest-cov

Security Analysis: bandit
