# Account Ownership Validation Vulnerability

##  Overview

**Severity:**  Critical  
**Difficulty:** Easy  
**Real-World Impact:** Cashio Dollar Exploit ($52M), Multiple Token Programs

Account ownership validation is the second most common vulnerability in Solana programs. It occurs when programs fail to verify that accounts are owned by the correct program, allowing attackers to pass fake accounts with malicious data.

---

##  The Vulnerability

### What Goes Wrong

Solana's account model requires explicit validation of account ownership. When you use raw `AccountInfo` without checking the owner field, attackers can:

1. Create a fake account with crafted data
2. Pass it to your program as if it were legitimate
3. Trick your program into processing malicious data

### Vulnerable Code Pattern
```rust
#[derive(Accounts)]
pub struct ProcessUser<'info> {
    ///  VULNERABLE: No ownership check
    pub user_account: AccountInfo<'info>,
}

pub fn claim_reward(ctx: Context<ProcessUser>) -> Result<()> {
    // Deserialize account data
    let user = User::try_deserialize(&mut &ctx.accounts.user_account.data.borrow()[..])?;
    
    // Calculate reward based on points
    let reward = user.points / 100;
    
    //  But is this data from OUR program or a fake account?
    mint_tokens(ctx, reward)?;
    Ok(())
}
```

### Why It's Dangerous
```
Legitimate Account:
- Owner: YourProgram
- Data: Valid user data
- Result:  Processed correctly

Malicious Account:
- Owner: AttackerProgram (or any other)
- Data: Crafted exploit data (points: 1,000,000,000)
- Result:  Program processes fake data!
```

**The Problem:**
- Account data can be deserialized successfully
- But the data comes from an untrusted source
- Attacker controls what the "points" value is
- Your program mints tokens based on fake data

---

##  The Fix

### Secure Code Pattern (Option 1: Recommended)
```rust
//  SECURE: Use Account<T>
#[derive(Accounts)]
pub struct ProcessUser<'info> {
    ///  Automatic ownership validation
    pub user_account: Account<'info, User>,
}

pub fn claim_reward(ctx: Context<ProcessUser>) -> Result<()> {
    let user = &ctx.accounts.user_account;
    
    // Safe to use - ownership already validated
    let reward = user.points / 100;
    mint_tokens(ctx, reward)?;
    Ok(())
}
```

### Secure Code Pattern (Option 2: Manual)
```rust
#[derive(Accounts)]
pub struct ProcessUser<'info> {
    ///  SECURE: Explicit owner check
    #[account(owner = crate::ID)]
    pub user_account: AccountInfo<'info>,
}
```

### Secure Code Pattern (Option 3: Runtime)
```rust
pub fn claim_reward(ctx: Context<ProcessUser>) -> Result<()> {
    //  Manual ownership check
    require!(
        ctx.accounts.user_account.owner == &crate::ID,
        ErrorCode::InvalidOwner
    );
    
    // Now safe to deserialize
    let user = User::try_deserialize(&ctx.accounts.user_account.data.borrow())?;
    Ok(())
}
```

### What `Account<'info, T>` Does

| Check | AccountInfo | Account<T> |
|-------|------------|------------|
| Owner validation |  Manual |  Automatic |
| Type safety |  None |  Enforced |
| Discriminator check |  Manual |  Automatic |
| Deserialization |  Manual |  Automatic |

**Behind the scenes:**
```rust
// Anchor automatically performs:

// 1. Check owner
if account.owner != program_id {
    return Err(ErrorCode::AccountOwnedByWrongProgram);
}

// 2. Check discriminator (first 8 bytes)
let discriminator = &account.data[..8];
if discriminator != User::DISCRIMINATOR {
    return Err(ErrorCode::AccountDiscriminatorMismatch);
}

// 3. Deserialize data
let user = User::try_deserialize(&account.data[8..])?;
```

---

##  Real-World Example: Cashio Dollar

**Date:** March 23, 2022  
**Loss:** $52 Million  
**Cause:** Missing account validation in mint function

### What Happened

Cashio Dollar was a stablecoin backed by collateral:
1. Users deposit collateral (real tokens)
2. System mints CASH stablecoins against collateral
3. Collateral tracked in special accounts

**The Vulnerability:**
```rust
// Simplified version of Cashio's vulnerability
pub fn mint_cash(ctx: Context<MintCash>, amount: u64) -> Result<()> {
    let collateral_account = &ctx.accounts.collateral_account;
    
    //  CRITICAL BUG: Never checked collateral_account owner!
    // Attacker could pass ANY account here
    
    // Read collateral value from account
    let collateral = get_collateral_value(collateral_account)?;
    
    // Check if enough collateral (fake account reports unlimited)
    require!(
        collateral >= amount * COLLATERAL_RATIO,
        ErrorCode::InsufficientCollateral
    );
    
    // Mint CASH tokens
    mint_tokens(ctx, amount)?;
    Ok(())
}

#[derive(Accounts)]
pub struct MintCash<'info> {
    /// CHECK:  Should validate owner = Cashio program!
    pub collateral_account: AccountInfo<'info>,
    // ...
}
```

### The Exploit

**Step 1:** Attacker created a **fake collateral account** in their own program
```rust
// Attacker's program
pub struct FakeCollateral {
    pub collateral_amount: u64,  // Set to $1 billion
}
```

**Step 2:** Attacker called Cashio's `mint_cash` with fake account
```typescript
const fakeCollateral = await createFakeCollateralAccount({
    collateral_amount: 1_000_000_000_000,  // Fake $1B
});

await cashioProgram.methods
    .mintCash(new BN(2_000_000_000))  // Mint 2 billion CASH
    .accounts({
        collateralAccount: fakeCollateral.publicKey,  //  Fake account
    })
    .rpc();
```

**Step 3:** Cashio program processed fake data
```rust
// Cashio's program:
let collateral = get_collateral_value(collateral_account)?;
// Returns: $1 billion (from fake account)

// Check passes!
require!(collateral >= 2_000_000_000 * COLLATERAL_RATIO);

// Mints 2 billion CASH tokens without real collateral
```

**Step 4:** Attacker dumped tokens

- Dumped 2 billion CASH on DEX for real USDC
- **$52 million stolen**
- Protocol became insolvent

### The Fix Needed
```rust
#[derive(Accounts)]
pub struct MintCash<'info> {
    ///  FIX: Use Account<T> to validate ownership
    pub collateral_account: Account<'info, CollateralVault>,
    
    // Or manually:
    #[account(owner = crate::ID)]
    pub collateral_account: AccountInfo<'info>,
}
```

---

##  Testing the Vulnerability

### Exploit Test (Vulnerable Version)
```typescript
import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";

describe("account-ownership-vulnerable", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.AccountOwnershipVulnerable;
  const attackerProgram = anchor.workspace.AttackerProgram;

  it("EXPLOIT: Accepts account from different program", async () => {
    const user = anchor.web3.Keypair.generate();
    
    // Attacker creates fake user account in THEIR program
    const fakeAccount = anchor.web3.Keypair.generate();
    
    await attackerProgram.methods
      .createFakeUser(new anchor.BN(1_000_000_000))  // Fake points
      .accounts({
        fakeUser: fakeAccount.publicKey,
        payer: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user, fakeAccount])
      .rpc();
    
    console.log(" Created fake user account with 1 billion points");
    
    // Call victim program with fake account
    const balanceBefore = await getTokenBalance(user.publicKey);
    
    await program.methods
      .claimReward()
      .accounts({
        userAccount: fakeAccount.publicKey,  //  Fake account!
        user: user.publicKey,
      })
      .signers([user])
      .rpc();
    
    const balanceAfter = await getTokenBalance(user.publicKey);
    const reward = balanceAfter - balanceBefore;
    
    expect(reward).to.equal(10_000_000);  // 1B points / 100 = 10M tokens
    console.log(" EXPLOIT SUCCESSFUL! Claimed 10M tokens from fake account!");
  });
});
```

### Security Test (Secure Version)
```typescript
describe("account-ownership-secure", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.AccountOwnershipSecure;
  const attackerProgram = anchor.workspace.AttackerProgram;

  it("PROTECTED: Rejects account from different program", async () => {
    const user = anchor.web3.Keypair.generate();
    
    // Create fake account (same as vulnerable test)
    const fakeAccount = anchor.web3.Keypair.generate();
    
    await attackerProgram.methods
      .createFakeUser(new anchor.BN(1_000_000_000))
      .accounts({
        fakeUser: fakeAccount.publicKey,
        payer: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user, fakeAccount])
      .rpc();
    
    console.log(" Created fake user account");
    console.log("  Attempting exploit on secure version...");
    
    // Try to use fake account (should FAIL)
    try {
      await program.methods
        .claimReward()
        .accounts({
          userAccount: fakeAccount.publicKey,
          user: user.publicKey,
        })
        .signers([user])
        .rpc();
      
      expect.fail("Should have thrown an error");
    } catch (err) {
      expect(err.toString()).to.include("AccountOwnedByWrongProgram");
      console.log(" PROTECTED! Fake account rejected");
    }
  });
  
  it("Accepts legitimate account from own program", async () => {
    const user = anchor.web3.Keypair.generate();
    
    // Create REAL user account in victim program
    await program.methods
      .initialize(new anchor.BN(1000))
      .accounts({
        userAccount: userAccountPDA,
        authority: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user])
      .rpc();
    
    // Should work with real account
    await program.methods
      .claimReward()
      .accounts({
        userAccount: userAccountPDA,
        user: user.publicKey,
      })
      .signers([user])
      .rpc();
    
    console.log(" Legitimate account accepted");
  });
});
```

---

##  Prevention Checklist

### Code Review Questions

**For every account you read data from:**

1. **Is this owned by my program?**
   - If yes → Use `Account<'info, T>`
   - If no → Add explicit `owner` constraint

2. **Am I deserializing data?**
   - Check owner FIRST, then deserialize

3. **Could attacker pass wrong account type?**
   - Check discriminator

4. **What if this account is from another program?**
   - Your program would process malicious data

### Quick Checks
```bash
# Find potentially vulnerable patterns
grep -r "AccountInfo.*try_deserialize" programs/
grep -r "pub.*account.*AccountInfo" programs/

# Each result should be reviewed for ownership validation
```

### Deployment Checklist

- [ ] All program-owned accounts use `Account<'info, T>`
- [ ] All `AccountInfo` have explicit `owner` constraints
- [ ] Owner checked BEFORE deserialization
- [ ] Discriminators validated
- [ ] Tests with fake accounts written
- [ ] Audit confirms all ownership checks

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
account-ownership-vulnerable
  ✓ EXPLOIT: Accepts account from different program (1423ms)
   EXPLOIT SUCCESSFUL! Claimed 10M tokens from fake account!
```

### Secure Version
```bash
cd ../secure
anchor build
anchor test
```

**Expected Output:**
```
account-ownership-secure
  ✓ PROTECTED: Rejects account from different program (1234ms)
    PROTECTED! Fake account rejected
  ✓ Accepts legitimate account from own program (987ms)
```

---

##  Key Takeaways

1. **Never trust account data without checking owner** - Always validate first
2. **Use `Account<'info, T>` for program-owned accounts** - Automatic validation
3. **Check owner BEFORE deserializing** - Don't process untrusted data
4. **Validate discriminators** - Ensure correct account type
5. **This vulnerability is extremely common** - Review every `AccountInfo` usage
6. **Test with fake accounts** - Verify they're rejected

### The Simple Fix
```rust
// Change this:
pub user_account: AccountInfo<'info>,

// To this:
pub user_account: Account<'info, User>,

// Or add constraint:
#[account(owner = crate::ID)]
pub user_account: AccountInfo<'info>,
```


