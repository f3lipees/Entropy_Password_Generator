
- It generates two large prime numbers, computes their product, and derives a unique 20-character password from the result.
- Employs 40 iterations of the Miller-Rabin algorithm to generate reliable prime numbers between 10,000,000 and 100,000,000.
- Supports generating up to 10 passwords in a single run for bulk operations.

# Requirements

- A C compiler (e.g., GCC, Clang, or MSVC).
- Access to the Windows API and advapi32.lib for cryptographic functions.
- Access to /dev/urandom or /dev/random for entropy.

# Installation
- Clone or download the source code from the repository.
- Compile the Program:
- Unix-like Systems
  
          gcc -o Entropy_Password_Generator entropypassgen.c

  - Windows

          cl entropypassgen.c /link advapi32.lib

# Usage

          ./entropypassgen

- For multiple passwords (up to 10) in batch mode:

          ./entropypassgen --batch 5

  
  ![entropy](https://github.com/user-attachments/assets/c42e861e-e3c4-4628-8b36-5cfe88900f03)
