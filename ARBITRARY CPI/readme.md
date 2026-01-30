# Arbitrary CPI Vulnerability

## Overview

**Severity:**  Critical  
**Difficulty:** Hard  
**Real-World Impact:** Crema Finance ($9M), Multiple DeFi Protocols

Cross-Program Invocations (CPIs) allow programs to call other programs. Accepting arbitrary program IDs for CPIs allows attackers to trick your program into calling malicious programs, leading to fund theft, oracle manipulation, and protocol exploitation.

---

##  The Vulnerability

### What Goes Wrong

When programs accept user-provided program IDs without validation:
- Attacker can pass a malicious program
- Your program calls the malicious program
- Attacker controls the execution
- Can manipulate state, steal funds, or bypass security

### Understanding CPIs

A CPI is when your program calls another program:
```rust
// Your program calls the Token program
invoke(
    &transfer_instruction,
    &[
        from_account,
        to_account,
        authority,
        token_program,  // ← Must validate this is the REAL Token program
    ],
)?;
```

**The security principle:** Only call trusted programs. Verify program IDs before making CPIs.

### Vulnerable Code Pattern
```rust
//     VULNERABLE CODE
#[derive(Accounts)]
pub struct ExecuteTransfer<'info> {
    #[account(mut)]
    pub from: Signer<'info>,
    /// CHECK: Destination
    #[account(mut)]
    pub to: AccountInfo<'info>,
    /// CHECK:     DANGER - accepts ANY program!
    pub token_program: AccountInfo<'info>,
}

pub fn execute_transfer(
    ctx: Context<ExecuteTransfer>,
    amount: u64,
) -> Result<()> {
    //     token_program could be ANYTHING!
    let ix = spl_token::instruction::transfer(
        &ctx.accounts.token_program.key(),  //     Using unvalidated program
        &ctx.accounts.from.key(),
        &ctx.accounts.to.key(),
        &ctx.accounts.from.key(),
        &[],
        amount,
    )?;
    
    invoke(&ix, &[/* accounts */])?;
    Ok(())
}
```

### The Attack

**Step 1: Attacker creates malicious program**
```rust
// Malicious "token" program
#[program]
pub mod fake_token {
    pub fn transfer(ctx: Context<FakeTransfer>, amount: u64) -> Result<()> {
        // Pretends to transfer tokens
        msg!("Transfer of {} tokens", amount);
        
        // Actually logs approval for later exploit
        log_approval(ctx.accounts.authority, amount);
        
        // Or: Calls back into victim program (reentrancy)
        // Or: Manipulates state
        // Or: Steals tokens via different mechanism
        
        Ok(())
    }
}
```

**Step 2: Attacker calls your program with fake program**
```typescript
const maliciousProgram = await deployMaliciousProgram();

await victimProgram.methods
    .executeTransfer(new BN(1000000))
    .accounts({
        from: victimTokenAccount,
        to: attackerTokenAccount,
        tokenProgram: maliciousProgram.publicKey,  //     Fake token program!
    })
    .rpc();
```

**Step 3: Your program executes malicious CPI**
```rust
// Your program calls what it thinks is the Token program
invoke(&transfer_instruction, &accounts)?;

// Actually calls attacker's program!
// Attacker's program:
// - Logs approvals for later use
// - Manipulates oracle prices
// - Calls back into your program (reentrancy)
// - Steals funds via different mechanism
```

---

##     Real-World Example: Crema Finance

**Date:** July 3, 2022  
**Amount:** $9 Million  
**Cause:** Improper CPI program validation

### What Happened

Crema Finance was a liquidity pool protocol with a vulnerability in how it obtained price information.

**The Vulnerable Pattern:**
```rust
// Simplified version
pub fn execute_swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
    // Get price from "oracle"
    //     oracle_program was user-provided and not validated!
    let price = get_oracle_price(
        &ctx.accounts.oracle_program,  //     Could be ANY program
        &ctx.accounts.oracle_account,
    )?;
    
    // Calculate swap output using price
    let output_amount = calculate_swap(amount, price)?;
    
    // Execute swap
    execute_transfer(ctx, output_amount)?;
    Ok(())
}

#[derive(Accounts)]
pub struct Swap<'info> {
    /// CHECK:     No validation!
    pub oracle_program: AccountInfo<'info>,
    // ...
}
```

**The Exploit:**

1. Attacker created a **fake oracle program**
2. Fake oracle returned **manipulated prices** (e.g., 1 SOL = $1,000,000)
3. Attacker called swap with fake oracle
4. Crema calculated swap using fake price
5. Attacker received massive amounts of tokens
6. Drained $9M from liquidity pools

**The Fix Needed:**
```rust
#[derive(Accounts)]
pub struct Swap<'info> {
    ///   Validate oracle program ID
    #[account(address = OFFICIAL_ORACLE_PROGRAM)]
    pub oracle_program: Program<'info, OracleProgram>,
}
```

---

##   The Fix

### Option 1: Use `Program<'info, T>` (Best for Known Programs)
```rust
use anchor_spl::token::Token;

//   SECURE CODE
#[derive(Accounts)]
pub struct SecureTransfer<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    ///   Only accepts SPL Token program
    pub token_program: Program<'info, Token>,
}

pub fn execute_transfer(
    ctx: Context<SecureTransfer>,
    amount: u64,
) -> Result<()> {
    let cpi_accounts = Transfer {
        from: ctx.accounts.from.to_account_info(),
        to: ctx.accounts.to.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    
    let cpi_program = ctx.accounts.token_program.to_account_info();
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
    
    token::transfer(cpi_ctx, amount)?;
    Ok(())
}
```

**What `Program<'info, Token>` does:**
```rust
// Behind the scenes:

// 1. Check program ID
if token_program.key() != spl_token::ID {
    return Err(ErrorCode::InvalidProgramId);
}

// 2. Check executable
if !token_program.executable {
    return Err(ErrorCode::AccountNotExecutable);
}

// 3. Check not writable
if token_program.is_writable {
    return Err(ErrorCode::AccountNotExecutable);
}
```

### Option 2: Whitelist Programs
```rust
// Define allowed programs
pub const ALLOWED_PROGRAMS: &[Pubkey] = &[
    spl_token::ID,
    spl_associated_token_account::ID,
    // Add other trusted programs
];

#[derive(Accounts)]
pub struct CallExternal<'info> {
    /// CHECK: Validated against whitelist in instruction
    pub target_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub fn call_external(ctx: Context<CallExternal>) -> Result<()> {
    //   Validate program is in whitelist
    require!(
        ALLOWED_PROGRAMS.contains(&ctx.accounts.target_program.key()),
        ErrorCode::UnauthorizedProgram
    );
    
    // Safe to call now
    invoke(&instruction, &accounts)?;
    Ok(())
}
```

### Option 3: Explicit Program ID Validation
```rust
pub const OFFICIAL_ORACLE: Pubkey = pubkey!("oracle11111111111111111111111111111111111111");

#[derive(Accounts)]
pub struct UseOracle<'info> {
    /// CHECK: Validated as official oracle in instruction
    pub oracle_program: AccountInfo<'info>,
}

pub fn use_oracle(ctx: Context<UseOracle>) -> Result<()> {
    //   Validate it's the official oracle
    require!(
        ctx.accounts.oracle_program.key() == OFFICIAL_ORACLE,
        ErrorCode::InvalidOracleProgram
    );
    
    // Safe to use now
    let price = get_price(&ctx.accounts.oracle_program)?;
    Ok(())
}
```

---

##     Testing the Vulnerability

### Exploit Test (Vulnerable Version)
```typescript
import * as anchor from "@coral-xyz/anchor";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { expect } from "chai";

describe("arbitrary-cpi-vulnerable", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.ArbitraryCpiVulnerable;
  const fakeTokenProgram = anchor.workspace.FakeTokenProgram;

  it("EXPLOIT: Accepts and calls fake token program", async () => {
    const user = anchor.web3.Keypair.generate();
    const attacker = anchor.web3.Keypair.generate();
    
    console.log("    Deploying fake token program...");
    console.log("    Fake program ID:", fakeTokenProgram.programId.toString());
    console.log("    Real Token program ID:", TOKEN_PROGRAM_ID.toString());
    
    // Victim calls transfer with fake program
    const callsBefore = await getFakeTokenCallCount();
    
    await program.methods
      .executeTransfer(new anchor.BN(1_000_000))
      .accounts({
        from: user.publicKey,
        to: attacker.publicKey,
        tokenProgram: fakeTokenProgram.programId,  //     Fake program!
      })
      .signers([user])
      .rpc();
    
    const callsAfter = await getFakeTokenCallCount();
    
    expect(callsAfter).to.be.greaterThan(callsBefore);
    console.log("    EXPLOIT SUCCESSFUL! Victim program called fake token program");
    console.log("   Malicious program executed instead of real Token program");
  });
  
  it("EXPLOIT: Fake oracle manipulation", async () => {
    const user = anchor.web3.Keypair.generate();
    const fakeOracle = anchor.workspace.FakeOracleProgram;
    
    // Fake oracle returns manipulated price
    await fakeOracle.methods
      .setPrice(new anchor.BN(1_000_000_000))  // $1M per token!
      .rpc();
    
    console.log("    Fake oracle set to return $1M price");
    
    // Call swap with fake oracle
    await program.methods
      .executeSwap(new anchor.BN(1_000))
      .accounts({
        user: user.publicKey,
        oracleProgram: fakeOracle.programId,  //     Fake oracle
      })
      .signers([user])
      .rpc();
    
    console.log("    EXPLOIT SUCCESSFUL! Swap executed with fake oracle price");
    console.log("   Attacker received massive tokens due to manipulated price");
  });
});
```

### Security Test (Secure Version)
```typescript
describe("arbitrary-cpi-secure", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.ArbitraryCpiSecure;
  const fakeTokenProgram = anchor.workspace.FakeTokenProgram;

  it("PROTECTED: Rejects fake token program", async () => {
    const user = anchor.web3.Keypair.generate();
    const attacker = anchor.web3.Keypair.generate();
    
    console.log("    Attempting to use fake token program...");
    
    try {
      await program.methods
        .executeTransfer(new anchor.BN(1_000_000))
        .accounts({
          from: userTokenAccount,
          to: attackerTokenAccount,
          authority: user.publicKey,
          tokenProgram: fakeTokenProgram.programId,  //     Fake program
        })
        .signers([user])
        .rpc();
      
      expect.fail("Should have rejected fake program");
    } catch (err) {
      expect(err.toString()).to.include("InvalidProgramId");
      console.log("  PROTECTED! Fake token program rejected");
    }
  });
  
  it("Accepts real Token program", async () => {
    const user = anchor.web3.Keypair.generate();
    
    // Should work with real Token program
    await program.methods
      .executeTransfer(new anchor.BN(1_000_000))
      .accounts({
        from: userTokenAccount,
        to: destinationTokenAccount,
        authority: user.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,  //   Real program
      })
      .signers([user])
      .rpc();
    
    console.log("  Real Token program accepted and executed correctly");
  });
  
  it("PROTECTED: Rejects fake oracle", async () => {
    const user = anchor.web3.Keypair.generate();
    const fakeOracle = anchor.workspace.FakeOracleProgram;
    
    console.log("    Attempting to use fake oracle...");
    
    try {
      await program.methods
        .executeSwap(new anchor.BN(1_000))
        .accounts({
          user: user.publicKey,
          oracleProgram: fakeOracle.programId,  //     Fake oracle
        })
        .signers([user])
        .rpc();
      
      expect.fail("Should have rejected fake oracle");
    } catch (err) {
      expect(err.toString()).to.include("UnauthorizedProgram");
      console.log("  PROTECTED! Fake oracle rejected");
    }
  });
});
```

---

##  Attack Scenarios

### Scenario 1: Fake Token Program
```rust
// Attacker's fake token program
pub fn transfer() -> Result<()> {
    // Instead of transferring, logs an approval
    msg!("Logging approval for later exploit");
    Ok(())
}

// Later, attacker uses logged approvals to drain real tokens
```

### Scenario 2: Oracle Manipulation
```rust
// Fake oracle always returns price beneficial to attacker
pub fn get_price() -> Result<u64> {
    Ok(1_000_000_000)  // Claims 1 token = $1B
}

// Victim protocol uses fake price for calculations
// Attacker drains liquidity
```

### Scenario 3: Reentrancy
```rust
// Malicious program calls BACK into victim program
pub fn fake_transfer() -> Result<()> {
    // Call back into victim program with inconsistent state
    invoke(&callback_instruction, &accounts)?;
    Ok(())
}
```

---

##  Prevention Checklist

### Before Making Any CPI

- [ ] Using `Program<'info, T>` for known programs?
- [ ] Validated program ID explicitly?
- [ ] Checked `executable` flag?
- [ ] Program in whitelist (if dynamic)?
- [ ] Tested with fake programs?
- [ ] Remaining accounts validated?
- [ ] No user-provided program IDs?

### Code Review
```bash
# Find potentially unsafe CPIs
grep -r "invoke\|invoke_signed" programs/
grep -r "AccountInfo.*program" programs/

# Review each for proper validation
```

### Available Program Types
```rust
use anchor_spl::token::Token;
use anchor_spl::associated_token::AssociatedToken;
use anchor_lang::system_program::System;

pub token_program: Program<'info, Token>,
pub associated_token_program: Program<'info, AssociatedToken>,
pub system_program: Program<'info, System>,
```

---

##  Running This Example

### Vulnerable Version
```bash
cd vulnerable
anchor build
anchor test
```

**Expected Output:**
```
arbitrary-cpi-vulnerable
  ✓ EXPLOIT: Accepts and calls fake token program (1645ms)
      EXPLOIT SUCCESSFUL! Victim program called fake token program
  ✓ EXPLOIT: Fake oracle manipulation (1432ms)
```

### Secure Version
```bash
cd ../secure
anchor build
anchor test
```

**Expected Output:**
```
arbitrary-cpi-secure
  ✓ PROTECTED: Rejects fake token program (1234ms)
    PROTECTED! Fake token program rejected
  ✓ Accepts real Token program (987ms)
  ✓ PROTECTED: Rejects fake oracle (1123ms)
```

---

## 🎓 Key Takeaways

1. **Never accept arbitrary program IDs** - Always validate
2. **Use `Program<'info, T>` for known programs** - Type-safe and automatic
3. **Whitelist programs explicitly** - If you need dynamic CPIs
4. **Validate executable flag** - Don't trust user input
5. **Test with malicious programs** - Verify rejection
6. **This is the hardest to secure properly** - Be extra careful

### The Simple Fix
```rust
// Change this:
pub token_program: AccountInfo<'info>,

// To this:
pub token_program: Program<'info, Token>,

// Or validate explicitly:
require!(
    token_program.key() == spl_token::ID,
    ErrorCode::InvalidProgram
);
```

---

##  Additional Resources

- [Anchor CPI Documentation](https://www.anchor-lang.com/docs/cross-program-invocations)
- [Solana CPI Guide](https://docs.solana.com/developing/programming-model/calling-between-programs)
- [Crema Finance Post-Mortem](https://medium.com/@cremadotfinance/post-mortem-of-crema-finance-hack-incident-82afb8a4b8f7)
- [Sealevel Attacks - Arbitrary CPI](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/9-arbitrary-cpi)

---

## Disclaimer

The vulnerable version contains **deliberately insecure code** for educational purposes only.

**DO NOT** accept arbitrary program IDs in production. Always validate CPIs.

---

**Previous:** [← PDA Validation](../04-pda-validation)  
**Back to:** [Main README](../README.md)

---

**  This completes all 5 vulnerability examples!**

You now have comprehensive documentation for teaching Solana security patterns.