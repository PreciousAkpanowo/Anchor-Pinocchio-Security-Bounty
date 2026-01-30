# Solana Security Examples: Learning Security Through Contrast

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solana](https://img.shields.io/badge/Solana-Security-purple)](https://solana.com)
[![Anchor](https://img.shields.io/badge/Framework-Anchor-blue)](https://www.anchor-lang.com/)

> **A comprehensive educational resource demonstrating common Solana program vulnerabilities and their fixes through side-by-side code comparisons.**

##  Project Overview

Security remains one of the biggest challenges in Solana program development. Many exploits don't come from complex attacks, but from simple mistakes: missing account validation, incorrect authority checks, unsafe arithmetic, or misunderstood CPI behavior.

This repository provides **5 complete vulnerability examples**, each containing:
-  A deliberately vulnerable program
-  A secure version with the fix
-  Comprehensive inline comments explaining the issue
-  Tests demonstrating both the exploit and the fix
-  Detailed documentation

**Goal:** Make security concepts practical and obvious, especially for developers learning Anchor.

---

##  Covered Vulnerabilities

| # | Vulnerability | Severity | Difficulty | Real-World Impact |
|---|--------------|----------|------------|-------------------|
| 1 | [Missing Signer Check](./01-missing-signer-check) |  Critical | Easy | Wormhole ($320M) |
| 2 | [Account Ownership Validation](./02-account-ownership) |  Critical | Easy | Cashio ($52M) |
| 3 | [Integer Overflow/Underflow](./03-integer-overflow) |  High | Medium | Multiple Protocols |
| 4 | [PDA Seed Validation](./04-pda-validation) |  High | Medium | Common Attack Vector |
| 5 | [Arbitrary CPI Calls](./05-arbitrary-cpi) |  Critical | Hard | Crema Finance ($9M) |

**Total Impact Referenced:** $400M+ in real-world hacks

---

##  Quick Start

### Prerequisites
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"

# Install Anchor
cargo install --git https://github.com/coral-xyz/anchor avm --locked --force
avm install latest
avm use latest

# Verify installations
anchor --version
solana --version
```

### Running Examples

Each vulnerability has its own directory with vulnerable and secure versions:
```bash
# Example: Testing Missing Signer Check
cd 01-missing-signer-check/vulnerable
anchor build
anchor test

# See the secure version
cd ../secure
anchor build
anchor test
```

---

##  Learning Path

### For Beginners
Start with these in order:
1. **Missing Signer Check** - Easiest to understand, most common
2. **Account Ownership** - Builds on #1
3. **Integer Overflow** - Introduces arithmetic safety

### For Intermediate Developers
4. **PDA Validation** - Requires understanding of PDAs
5. **Arbitrary CPI** - Most complex, requires CPI knowledge

---

##  Repository Structure
```
solana-security-examples/
│
├── README.md                          # You are here
├── LICENSE                            # MIT License
├── CONTRIBUTING.md                    # Contribution guidelines
│
├── docs/
│   └── SECURITY_DEEP_DIVE.md          # 25,000+ word comprehensive guide
│
├── 01-missing-signer-check/
│   ├── README.md                      # Detailed vulnerability explanation
│   ├── vulnerable/
│   │   ├── Anchor.toml
│   │   ├── Cargo.toml
│   │   ├── programs/
│   │   │   └── missing-signer-vulnerable/
│   │   │       └── src/
│   │   │           └── lib.rs         # Vulnerable code
│   │   └── tests/
│   │       └── exploit.ts             # Exploit demonstration
│   └── secure/
│       ├── Anchor.toml
│       ├── Cargo.toml
│       ├── programs/
│       │   └── missing-signer-secure/
│       │       └── src/
│       │           └── lib.rs         # Fixed code
│       └── tests/
│           └── security.ts            # Security test
│
├── 02-account-ownership/              # Same structure
├── 03-integer-overflow/               # Same structure
├── 04-pda-validation/                 # Same structure
└── 05-arbitrary-cpi/                  # Same structure
```

---

##  What You'll Learn

### Security Concepts
-  Signature verification and authority validation
-  Account ownership and type checking
-  Safe arithmetic operations
-  PDA derivation and validation
-  Secure cross-program invocations

### Anchor Features
-  Account types (`Signer`, `Account`, `AccountInfo`, `Program`)
-  Constraints (`#[account(signer)]`, `owner = program_id`, `seeds`, `bump`)
-  Checked math operations
-  PDA seeds and bump validation
-  CPI best practices

### Testing & Exploitation
-  Writing exploit tests
-  Demonstrating vulnerabilities
-  Verifying security fixes
-  Best practices for program testing

---

##  Vulnerability Deep Dives

### 1. Missing Signer Check

**What it is:** Failing to verify that an account actually signed a transaction.

**Why it's dangerous:** Attackers can impersonate any account and execute unauthorized actions.

**The fix:**
```rust
//  VULNERABLE
pub authority: AccountInfo<'info>,

//  SECURE
pub authority: Signer<'info>,
```

**Real-world impact:** Wormhole Bridge hack ($320M) - signature verification bypass

[→ Full explanation](./01-missing-signer-check)

---

### 2. Account Ownership Validation

**What it is:** Not checking that accounts are owned by the correct program.

**Why it's dangerous:** Attackers can pass fake accounts with malicious data.

**The fix:**
```rust
//  VULNERABLE
pub user_account: AccountInfo<'info>,

//  SECURE
pub user_account: Account<'info, User>,
```

**Real-world impact:** Cashio Dollar exploit ($52M) - fake collateral account

[→ Full explanation](./02-account-ownership)

---

### 3. Integer Overflow/Underflow

**What it is:** Arithmetic operations that wrap on overflow instead of failing.

**Why it's dangerous:** Can create tokens from nothing, bypass limits, manipulate balances.

**The fix:**
```rust
//  VULNERABLE
user.balance = user.balance + amount;

//  SECURE
user.balance = user.balance
    .checked_add(amount)
    .ok_or(ErrorCode::Overflow)?;
```

**Real-world impact:** Multiple token programs - infinite minting, balance manipulation

[→ Full explanation](./03-integer-overflow)

---

### 4. PDA Seed Validation

**What it is:** Not validating that PDAs are derived correctly from expected seeds.

**Why it's dangerous:** Attackers can create fake PDAs and access unauthorized resources.

**The fix:**
```rust
//  VULNERABLE
#[account(mut)]
pub vault: Account<'info, Vault>,

//  SECURE
#[account(
    mut,
    seeds = [b"vault", authority.key().as_ref()],
    bump = vault.bump,
)]
pub vault: Account<'info, Vault>,
```

**Real-world impact:** Common attack vector in DeFi protocols

[→ Full explanation](./04-pda-validation)

---

### 5. Arbitrary CPI Calls

**What it is:** Accepting user-provided program IDs for cross-program invocations.

**Why it's dangerous:** Attackers can trick your program into calling malicious programs.

**The fix:**
```rust
//  VULNERABLE
pub target_program: AccountInfo<'info>,

//  SECURE
pub token_program: Program<'info, Token>,
```

**Real-world impact:** Crema Finance hack ($9M) - fake oracle manipulation

[→ Full explanation](./05-arbitrary-cpi)

---

##  Key Takeaways

### The Five Golden Rules

1. **Always validate signatures** - Use `Signer<'info>` for authority accounts
2. **Always validate ownership** - Use `Account<'info, T>` for program-owned accounts
3. **Always use checked math** - Use `.checked_add()`, `.checked_sub()`, etc.
4. **Always validate PDAs** - Use `seeds` and `bump` constraints
5. **Always validate CPIs** - Use `Program<'info, T>` or explicit validation

### Security Checklist

Before deploying any Solana program:

- [ ] All authority accounts use `Signer<'info>`
- [ ] All program-owned accounts use `Account<'info, T>`
- [ ] All PDAs have `seeds` and `bump` constraints
- [ ] All arithmetic uses `checked_*` methods
- [ ] All CPIs validate program IDs
- [ ] No `unwrap()` on financial operations
- [ ] Comprehensive tests including exploit attempts
- [ ] Security audit completed

---

##  Testing Your Programs

### Test Structure
```typescript
describe("Security Tests", () => {
    describe("Positive Tests (Should Pass)", () => {
        it("Allows legitimate user to withdraw", async () => {
            // Test the happy path
        });
    });
    
    describe("Negative Tests (Should Fail)", () => {
        it("Rejects unauthorized signer", async () => {
            // Test missing signature
        });
        
        it("Rejects wrong account owner", async () => {
            // Test invalid ownership
        });
        
        it("Rejects overflow", async () => {
            // Test arithmetic boundaries
        });
    });
});
```

### Example Exploit Test
```typescript
it("EXPLOIT: Drains vault without signature", async () => {
    const attacker = Keypair.generate();
    const victim = Keypair.generate();
    
    // Initialize victim's vault
    await program.methods.initialize()
        .accounts({ authority: victim.publicKey })
        .signers([victim])
        .rpc();
    
    // Attacker withdraws WITHOUT victim's signature
    await program.methods.withdraw(new BN(1_000_000))
        .accounts({
            vault: vaultPDA,
            authority: victim.publicKey,  //  Victim's key, no signature!
        })
        .signers([attacker])  //  Only attacker signs
        .rpc();
    
    // Exploit succeeds! 
});
```

---

##  Real-World Impact

These aren't theoretical vulnerabilities. Each has caused real losses:

### Major Hacks Referenced

| Exploit | Amount | Date | Vulnerability |
|---------|--------|------|---------------|
| **Wormhole Bridge** | $320M | Feb 2022 | Missing signature verification |
| **Cashio Dollar** | $52M | Mar 2022 | Missing account validation |
| **Crema Finance** | $9M | Jul 2022 | Improper CPI validation |
| **Others** | $20M+ | 2021-2024 | Integer overflows, PDA issues |

**Total:** Over $400 million lost to these five vulnerability patterns.

### Why This Matters

> "Most Solana exploits come from simple mistakes in account validation, not sophisticated attacks. Understanding these patterns is essential for every Solana developer."

Every vulnerability in this repository:
-  Has caused real-world losses
-  Is completely preventable
-  Can be fixed with simple patterns
-  Is testable with basic exploit tests

---

##  Documentation

### In This Repository

- **[SECURITY_DEEP_DIVE.md](./docs/SECURITY_DEEP_DIVE.md)** - 25,000+ word comprehensive guide covering:
  - Detailed explanations of each vulnerability
  - Real-world hack case studies
  - Complete code examples
  - Testing strategies
  - Security development lifecycle

- **Individual READMEs** - Each vulnerability directory contains:
  - Detailed vulnerability explanation
  - Attack scenarios
  - Step-by-step fixes
  - Testing patterns
  - Prevention checklists

### External Resources

- **[Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)** - Official Solana docs
- **[Anchor Security](https://www.anchor-lang.com/docs/security)** - Anchor-specific security
- **[Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)** - Similar vulnerability repository

### Security Auditors

- [Neodyme](https://neodyme.io/) - Solana security specialists
- [OtterSec](https://osec.io/) - Smart contract auditing
- [Soteria](https://www.soteria.dev/) - Automated security tools

---

##  Development Tools

### Static Analysis
```bash
# Install Soteria
cargo install soteria

# Run analysis
cd programs/your-program
soteria -analyzeAll .

# Review findings for:
# - Missing signer checks
# - Unchecked arithmetic
# - Missing owner validations
```

### Testing Tools
```bash
# Run Anchor tests with detailed output
anchor test --skip-local-validator

# Run tests with coverage
# (requires additional setup)
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### Useful Commands
```bash
# Build all programs
anchor build

# Test specific program
cd 01-missing-signer-check/vulnerable
anchor test

# Clean build artifacts
anchor clean

# Deploy to devnet
anchor deploy --provider.cluster devnet
```

---

##  Contributing

Contributions are welcome! This project aims to be the most comprehensive Solana security resource.

### Ways to Contribute

1. **Add new vulnerability examples** - Found a pattern we missed?
2. **Improve documentation** - Clarify explanations, fix typos
3. **Add tests** - More test coverage is always good
4. **Share real-world examples** - Reference actual exploits
5. **Translate** - Help make this accessible to more developers

### Contribution Guidelines

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed guidelines.

**Quick rules:**
- Keep examples simple and focused
- Include both vulnerable and secure versions
- Add comprehensive comments
- Write tests demonstrating the issue
- Reference real-world impacts when possible

---

##  License

This project is licensed under the MIT License - see [LICENSE](./LICENSE) file for details.

### Important Notice

This repository contains **deliberately vulnerable code** for educational purposes.

 **DO NOT** use the vulnerable examples in production  
 **DO NOT** copy code without understanding it  
 **DO** use the secure versions as reference  
 **DO** get professional audits before deploying



---

##  Acknowledgments

- **Built for:** SuperteamNG Solana Security Bounty
- **Inspired by:** Real-world Solana exploits and security research
- **Thanks to:** 
  - Solana Foundation for comprehensive security documentation
  - Anchor team for security-first framework design
  - Security auditors who publish findings and help the ecosystem learn
  - The Solana developer community for feedback and contributions

### References

This project references and learns from:
- Wormhole Bridge incident reports and post-mortems
- Cashio Dollar exploit analysis
- Crema Finance security disclosure
- Neodyme security research
- OtterSec blog posts on Solana vulnerabilities
- Solana StackExchange security discussions



---

##  Project Goals

This repository aims to:

1.  **Educate developers** on common Solana security vulnerabilities
2.  **Prevent future hacks** by making security patterns obvious
3.  **Provide reference code** for secure Solana development
4.  **Build security awareness** in the Solana ecosystem
5.  **Lower the barrier** to writing secure smart contracts

### Success Metrics

- Developers learn to identify these vulnerabilities in code reviews
- New projects avoid these patterns from day one
- Audit findings decrease over time
- The Solana ecosystem becomes more secure

---

##  Getting Started Checklist

If you'ready to learn, Follow this checklist:

- [ ] Clone this repository
- [ ] Install prerequisites (Rust, Solana, Anchor)
- [ ] Read [01-missing-signer-check/README.md](./01-missing-signer-check)
- [ ] Build and test the vulnerable version
- [ ] Build and test the secure version
- [ ] Understand the difference
- [ ] Repeat for vulnerabilities 2-5
- [ ] Read [SECURITY_DEEP_DIVE.md](./docs/SECURITY_DEEP_DIVE.md)
- [ ] Apply learnings to your own projects
- [ ] Share this resource with other developers

---



*Last Updated: January 2026*  
*Maintained by: [@preciousftw](https://twitter.com/preciousftw)*  
*License: MIT*

</div>