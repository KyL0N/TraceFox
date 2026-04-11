# Contributing to TraceFox

First off, thank you for considering contributing to TraceFox! 

We welcome contributions from anyone, whether it's bug reports, feature requests, or code contributions.

## How to Contribute

### 1. Reporting Bugs
- Use the GitHub issue search to check whether the bug has already been reported.
- If not, open a new issue. Please include details about your environment, the TraceFox version, and the steps to reproduce the bug.

### 2. Suggesting Enhancements
- Open an issue describing the feature you would like to see.
- Provide use cases and explain why this enhancement would be useful to most users.

### 3. Code Contributions
1. Fork the repository and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes (`make` in `agent/` and python unittests in `server/`).
4. Format your code to match the existing style (we use clang-format for C/C++).
5. Issue that pull request!

## C/C++ Development Guidelines (Agent)
- The agent is designed for edge/embedded systems. **Avoid heap allocations (`malloc`/`free`) in the hot collection paths** to prevent memory fragmentation and latency.
- Ensure cross-platform compatibility where possible, but prioritize Linux kernel `/proc` and `statvfs` specifics.
- Always check return values of system calls and handle errors gracefully.
- Follow the `TF_LOG_*` macro pattern for logging, instead of raw `printf`.
- Compile with `-Wall -Wextra -Werror` to catch potential issues early. Our CI pipeline enforces this.

## Python Development Guidelines (Server)
- Keep dependencies minimal to ensure easy deployment.
- Maintain backward compatibility in the `tracefox_protocol.py` parser.

## Code of Conduct
Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms.

Thank you for making TraceFox better!
