# Integer Overflow/Underflow Vulnerability

##  Overview

**Severity:**  High  
**Difficulty:** Medium  
**Real-World Impact:** Multiple Token Programs, DeFi Protocols

Integer overflow and underflow vulnerabilities occur when arithmetic operations exceed the bounds of their data types, causing values to wrap around. In smart contracts handling money, this is **catastrophic**.

---

##  The Vulnerability

### What Goes Wrong

Rust's default arithmetic operators (`+`, `-`, `*`, `/`) **wrap on overflow**:
```rust
let max = u64::MAX;  // 18,446,744,073,709,551,615
let result = max + 1;  // 0 (wrapped around!)

let min: u64 = 0;
let result = min - 1;  // 18,446,744,073,709,551,615 (wrapped around!)
```

### Vulnerable Code Pattern
```rust
pub fn add_tokens(ctx: Context<UpdateBalance>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    
    // VULNERABLE: Can overflow
    // If user.balance = u64::MAX and amount = 1
    // Result: user.balance = 0 (wraps!)
    user.balance = user.balance + amount;
    
    Ok(())
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    
    // VULNERABLE: Can underflow
    // If user.balance = 100 and amount = 200
    // Result: user.balance = huge number (wraps!)
    user.balance = user.balance - amount;
    
    transfer_tokens(ctx, amount)?;
    Ok(())
}
```

### Why It's Dangerous

**Attack Scenario 1: Balance Overflow**
```
User balance: u64::MAX (18,446,744,073,709,551,615)
Add: 1 token
Result: 0 tokens 

Attack: User resets their balance to zero
```

**Attack Scenario 2: Supply Cap Bypass**
```rust
// Check supply cap
require!(
    token.total_supply + amount <= token.max_supply,
    ErrorCode::SupplyCapExceeded
);

// Problem: Addition can overflow!
// max_supply: 1,000,000
// total_supply: 999,999
// amount: 18,446,744,073,709,551,617
// 
// Check: 999,999 + huge_number = 1,000 (overflow!)
// 1,000 <= 1,000,000? YES 
// Mints quintillions of tokens! 
```

**Attack Scenario 3: Underflow to Huge Value**
```
User balance: 100 tokens
Withdraw: 200 tokens
Result: 18,446,744,073,709,551,515 tokens 

Attack: User gains quintillions of tokens from underflow
```

---

##  The Fix

### Use Checked Arithmetic
```rust
//  SECURE: Addition
pub fn add_tokens(ctx: Context<UpdateBalance>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    
    // Returns None on overflow
    user.balance = user.balance
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;
    
    Ok(())
}

//  SECURE: Subtraction
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    
    // Returns None on underflow
    user.balance = user.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::InsufficientFunds)?;
    
    transfer_tokens(ctx, amount)?;
    Ok(())
}

//  SECURE: Multiplication
pub fn calculate_reward(ctx: Context<Calculate>, multiplier: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    
    // Returns None on overflow
    user.tokens = user.points
        .checked_mul(multiplier)
        .ok_or(ErrorCode::Overflow)?;
    
    Ok(())
}

//  SECURE: Division (also prevents div by zero!)
pub fn calculate_average(ctx: Context<Calculate>, divisor: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;
    
    // Returns None on division by zero
    user.average = user.total
        .checked_div(divisor)
        .ok_or(ErrorCode::DivisionByZero)?;
    
    Ok(())
}
```

### Checked Math Methods

| Operation | Wrapping (Unsafe) | Checked (Safe) | Returns |
|-----------|-------------------|----------------|---------|
| Addition | `a + b` | `a.checked_add(b)` | `Option<u64>` |
| Subtraction | `a - b` | `a.checked_sub(b)` | `Option<u64>` |
| Multiplication | `a * b` | `a.checked_mul(b)` | `Option<u64>` |
| Division | `a / b` | `a.checked_div(b)` | `Option<u64>` |

**Returns:**
- `Some(result)` - Operation succeeded
- `None` - Overflow/underflow/div-by-zero occurred

---

##  Real-World Impact

While there isn't one single "$XX million overflow hack," integer overflow has been a component in multiple exploits:

### Early Token Programs
- Supply tracking overflows allowing infinite minting
- Balance checks bypassed via overflow
- Unauthorized withdrawals via underflow

### DeFi Protocols
- Price calculation overflows → incorrect valuations
- Reward calculations wrapping to zero
- Slippage checks bypassed

### Common Pattern
```rust
// Vulnerable pattern seen across protocols
pub fn calculate_output(input: u64, rate: u64) -> Result<u64> {
    //  Can overflow
    let output = input * rate / PRECISION;
    Ok(output)
}

// Attack:
// input = u64::MAX / 2
// rate = 3
// input * rate overflows BEFORE division!
```

---

##  Testing the Vulnerability

### Exploit Test (Vulnerable Version)
```typescript
import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";

describe("integer-overflow-vulnerable", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.IntegerOverflowVulnerable;
  const MAX_U64 = new anchor.BN("18446744073709551615");

  it("EXPLOIT: Overflow wraps to 0", async () => {
    const user = anchor.web3.Keypair.generate();
    
    // Initialize user with MAX balance
    await program.methods
      .initialize()
      .accounts({
        user: userPDA,
        authority: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user])
      .rpc();
    
    // Manually set balance to MAX (for testing)
    await program.methods
      .setBalance(MAX_U64)
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    console.log(" User balance set to u64::MAX");
    
    // Try to add 1 (should overflow to 0)
    await program.methods
      .addPoints(new anchor.BN(1))
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    const userAccount = await program.account.user.fetch(userPDA);
    
    expect(userAccount.points.toString()).to.equal("0");
    console.log(" EXPLOIT SUCCESSFUL! Balance wrapped from MAX to 0");
  });
  
  it("EXPLOIT: Underflow wraps to huge number", async () => {
    const user = anchor.web3.Keypair.generate();
    
    // Initialize with small balance
    await program.methods
      .initialize()
      .accounts({
        user: userPDA,
        authority: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user])
      .rpc();
    
    await program.methods
      .setBalance(new anchor.BN(100))
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    console.log(" User balance: 100");
    
    // Try to remove 200 (should underflow)
    await program.methods
      .removePoints(new anchor.BN(200))
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    const userAccount = await program.account.user.fetch(userPDA);
    
    // Should be massive number (100 - 200 wrapped around)
    expect(userAccount.points.gt(new anchor.BN("1000000000000"))).to.be.true;
    console.log(" EXPLOIT SUCCESSFUL! Balance underflowed to:", userAccount.points.toString());
  });
  
  it("EXPLOIT: Multiplication overflow bypasses cap", async () => {
    const user = anchor.web3.Keypair.generate();
    
    await program.methods
      .initialize()
      .accounts({
        user: userPDA,
        authority: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user])
      .rpc();
    
    // Set points to half of MAX
    const halfMax = MAX_U64.div(new anchor.BN(2));
    await program.methods
      .setBalance(halfMax)
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    console.log(" User points: u64::MAX / 2");
    
    // Multiply by 3 (should overflow)
    await program.methods
      .calculateTokens(new anchor.BN(3))
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    const userAccount = await program.account.user.fetch(userPDA);
    
    // Should have wrapped around to small number
    console.log(" EXPLOIT SUCCESSFUL! Tokens after overflow:", userAccount.tokens.toString());
  });
});
```

### Security Test (Secure Version)
```typescript
describe("integer-overflow-secure", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.IntegerOverflowSecure;
  const MAX_U64 = new anchor.BN("18446744073709551615");

  it("PROTECTED: Overflow returns error", async () => {
    const user = anchor.web3.Keypair.generate();
    
    await program.methods
      .initialize()
      .accounts({
        user: userPDA,
        authority: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user])
      .rpc();
    
    await program.methods
      .setBalance(MAX_U64)
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    console.log("  User balance at MAX, trying to add 1...");
    
    try {
      await program.methods
        .addPoints(new anchor.BN(1))
        .accounts({ user: userPDA, authority: user.publicKey })
        .signers([user])
        .rpc();
      
      expect.fail("Should have thrown overflow error");
    } catch (err) {
      expect(err.toString()).to.include("Overflow");
      console.log(" PROTECTED! Overflow caught and rejected");
    }
  });
  
  it("PROTECTED: Underflow returns error", async () => {
    const user = anchor.web3.Keypair.generate();
    
    await program.methods
      .initialize()
      .accounts({
        user: userPDA,
        authority: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user])
      .rpc();
    
    await program.methods
      .setBalance(new anchor.BN(100))
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    console.log("  Balance: 100, trying to remove 200...");
    
    try {
      await program.methods
        .removePoints(new anchor.BN(200))
        .accounts({ user: userPDA, authority: user.publicKey })
        .signers([user])
        .rpc();
      
      expect.fail("Should have thrown underflow error");
    } catch (err) {
      expect(err.toString()).to.include("InsufficientPoints");
      console.log(" PROTECTED! Underflow caught and rejected");
    }
  });
  
  it("Accepts valid arithmetic", async () => {
    const user = anchor.web3.Keypair.generate();
    
    await program.methods
      .initialize()
      .accounts({
        user: userPDA,
        authority: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user])
      .rpc();
    
    // Normal operations should work
    await program.methods
      .addPoints(new anchor.BN(1000))
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    await program.methods
      .removePoints(new anchor.BN(500))
      .accounts({ user: userPDA, authority: user.publicKey })
      .signers([user])
      .rpc();
    
    const userAccount = await program.account.user.fetch(userPDA);
    expect(userAccount.points.toNumber()).to.equal(500);
    console.log(" Valid arithmetic works correctly");
  });
});
```

---

##  Prevention Checklist

### For Every Arithmetic Operation

- [ ] Addition (+) → Use `checked_add()`
- [ ] Subtraction (-) → Use `checked_sub()`
- [ ] Multiplication (*) → Use `checked_mul()`
- [ ] Division (/) → Use `checked_div()`
- [ ] Handle the `None` case explicitly
- [ ] Test with boundary values (0, 1, MAX, MAX-1)

### Code Review
```bash
# Find potentially unsafe arithmetic
grep -r " + \| - \| \* \| / " programs/**/*.rs | grep "u64\|u128"

# Should return no results in financial code
```

### Deployment Checklist

- [ ] All token/balance operations use checked math
- [ ] All supply tracking uses checked math
- [ ] All price calculations use checked math
- [ ] Division by zero handled
- [ ] Tests include boundary values
- [ ] Tests include overflow attempts

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
integer-overflow-vulnerable
  ✓ EXPLOIT: Overflow wraps to 0 (1234ms)
   EXPLOIT SUCCESSFUL! Balance wrapped from MAX to 0
  ✓ EXPLOIT: Underflow wraps to huge number (1456ms)
  ✓ EXPLOIT: Multiplication overflow bypasses cap (1567ms)
```

### Secure Version
```bash
cd ../secure
anchor build
anchor test
```

**Expected Output:**
```
integer-overflow-secure
  ✓ PROTECTED: Overflow returns error (1234ms)
   PROTECTED! Overflow caught and rejected
  ✓ PROTECTED: Underflow returns error (1345ms)
   PROTECTED! Underflow caught and rejected
  ✓ Accepts valid arithmetic (987ms)
```

---

##  Key Takeaways

1. **Rust's default arithmetic wraps** - Silent failures are dangerous
2. **Always use `checked_*` for financial math** - No exceptions
3. **Test boundary values** - MAX, MIN, 0, overflow points
4. **Handle errors explicitly** - Don't ignore `None` results
5. **This affects ALL token/balance operations** - Review every arithmetic operation

### The Simple Fix
```rust
// Change this:
balance = balance + amount;

// To this:
balance = balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;

// That's it. You're secure.
```

---

##  Additional Resources

- [Rust Overflow Docs](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Solana Cookbook - Checked Math](https://solanacookbook.com/references/programs.html#how-to-do-checked-math)
- [Anchor Error Handling](https://www.anchor-lang.com/docs/errors)

---
