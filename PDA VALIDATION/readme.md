# PDA Seed Validation Vulnerability

##  Overview

**Severity:**  High  
**Difficulty:** Medium  
**Real-World Impact:** Common Attack Vector in DeFi Protocols

Program Derived Addresses (PDAs) are deterministic addresses computed from seeds. Without proper validation, attackers can create fake PDAs or access unauthorized resources, leading to fund theft and protocol manipulation.

---

##  The Vulnerability

### What Goes Wrong

PDAs are supposed to be unique, deterministic addresses. Without proper validation:
- Attacker can pass ANY account claiming it's a PDA
- Program can't tell if it's the CORRECT PDA
- Leads to unauthorized access

### Understanding PDAs

PDAs are addresses that:
- Are **deterministic** (same seeds → same address)
- Have **no private key** (can't be signed by users)
- Can **only be signed by the program** that derived them
- Are used for **program-owned accounts**
```rust
// How PDAs are derived
let (pda, bump) = Pubkey::find_program_address(
    &[
        b"vault",                    // Seed 1: Static string
        user.key().as_ref(),         // Seed 2: User's pubkey
    ],
    program_id,
);
```

### Vulnerable Code Pattern
```rust
//     VULNERABLE CODE
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,  //     No seeds validation!
    pub authority: Signer<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    //     Only checks authority match
    require!(
        vault.authority == ctx.accounts.authority.key(),
        ErrorCode::Unauthorized
    );
    
    //     But is this the CORRECT vault for this authority?
    vault.balance = vault.balance.checked_sub(amount).unwrap();
    Ok(())
}
```

### The Attack

**Step 1: Attacker creates a fake vault**
```rust
// Attacker initializes their OWN vault
let fake_vault = Account {
    authority: attacker.pubkey,  // Attacker is authority
    balance: 1_000_000_000,      // Claims huge balance
    bump: 255,                   // Random bump
};
```

**Step 2: Attacker calls withdraw with fake vault**
```typescript
await program.methods
    .withdraw(new BN(1_000_000))
    .accounts({
        vault: fakeVaultAddress,  //     Attacker's fake vault
        authority: attacker.publicKey,
    })
    .signers([attacker])
    .rpc();
```

**Step 3: Program execution**
```rust
// Check 1: vault.authority == authority.key()?
// YES   (Both are attacker's pubkey)

// Check 2: Is this the correct PDA for this authority?
// NEVER CHECKED    

// Result: Withdrawal from fake vault succeeds!
```

**Why this is bad:**
- Attacker bypassed the legitimate vault
- Can create unlimited fake vaults with any balance
- Can manipulate state without depositing
- Other users' vaults remain untouched

---

##   The Fix

### Use Seeds and Bump Constraints
```rust
//   SECURE CODE
#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn withdraw(ctx: Context<SecureWithdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    //   seeds constraint guarantees this is the CORRECT PDA
    vault.balance = vault.balance.checked_sub(amount).unwrap();
    Ok(())
}
```

### What Seeds Validation Does
```rust
// Behind the scenes, Anchor performs:

// 1. Derive the expected PDA
let (expected_pda, expected_bump) = Pubkey::find_program_address(
    &[b"vault", authority.key().as_ref()],
    program_id,
);

// 2. Check it matches the provided account
if vault.key() != expected_pda {
    return Err(ErrorCode::ConstraintSeeds);
}

// 3. Verify bump matches
if vault.bump != expected_bump {
    return Err(ErrorCode::ConstraintSeeds);
}

// Only if all checks pass, instruction executes
```

---

## 🔧 Complete PDA Pattern

### Initialization
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump,  // Anchor finds canonical bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    vault.bump = ctx.bumps.vault;  //   Store the bump!
    Ok(())
}
```

### Usage
```rust
#[derive(Accounts)]
pub struct UseVault<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,  //   Use stored bump
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
```

### Account Structure
```rust
#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8,  //   Always store bump
}
```

---

##  Testing the Vulnerability

### Exploit Test (Vulnerable Version)
```typescript
import * as anchor from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { expect } from "chai";

describe("pda-validation-vulnerable", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.PdaValidationVulnerable;

  it("EXPLOIT: Accepts fake PDA", async () => {
    const attacker = anchor.web3.Keypair.generate();
    
    // Derive the CORRECT PDA for attacker
    const [correctVaultPDA, correctBump] = await PublicKey.findProgramAddress(
      [Buffer.from("vault"), attacker.publicKey.toBuffer()],
      program.programId
    );
    
    console.log("    Correct vault PDA:", correctVaultPDA.toString());
    
    // Initialize correct vault (empty)
    await program.methods
      .initialize()
      .accounts({
        vault: correctVaultPDA,
        authority: attacker.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([attacker])
      .rpc();
    
    console.log(" Correct vault initialized with 0 balance");
    
    // Attacker creates a FAKE vault with huge balance
    const fakeVault = anchor.web3.Keypair.generate();
    
    await program.methods
      .initializeFake(new anchor.BN(1_000_000_000))  // 1 billion balance
      .accounts({
        vault: fakeVault.publicKey,
        authority: attacker.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([attacker, fakeVault])
      .rpc();
    
    console.log(" Fake vault created:", fakeVault.publicKey.toString());
    console.log(" Fake vault has 1 billion balance");
    
    // Try to withdraw from FAKE vault (should work in vulnerable version)
    await program.methods
      .withdraw(new anchor.BN(1_000_000))
      .accounts({
        vault: fakeVault.publicKey,  //  Fake vault, not the correct PDA!
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();
    
    const fakeVaultAccount = await program.account.vault.fetch(fakeVault.publicKey);
    
    expect(fakeVaultAccount.balance.toNumber()).to.equal(999_000_000);
    console.log("    EXPLOIT SUCCESSFUL! Withdrew from fake vault");
    console.log("   Correct vault: untouched");
    console.log("   Fake vault: drained");
  });
});
```

### Security Test (Secure Version)
```typescript
describe("pda-validation-secure", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.PdaValidationSecure;

  it("PROTECTED: Rejects fake PDA", async () => {
    const attacker = anchor.web3.Keypair.generate();
    
    // Derive correct PDA
    const [correctVaultPDA, correctBump] = await PublicKey.findProgramAddress(
      [Buffer.from("vault"), attacker.publicKey.toBuffer()],
      program.programId
    );
    
    // Initialize correct vault
    await program.methods
      .initialize()
      .accounts({
        vault: correctVaultPDA,
        authority: attacker.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([attacker])
      .rpc();
    
    await program.methods
      .deposit(new anchor.BN(5_000_000))
      .accounts({
        vault: correctVaultPDA,
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();
    
    console.log(" Correct vault has 5M balance");
    
    // Create fake vault
    const fakeVault = anchor.web3.Keypair.generate();
    
    await program.methods
      .initializeFake(new anchor.BN(1_000_000_000))
      .accounts({
        vault: fakeVault.publicKey,
        authority: attacker.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([attacker, fakeVault])
      .rpc();
    
    console.log(" Fake vault created with 1B balance");
    console.log("  Attempting exploit on secure version...");
    
    // Try to use fake vault (should FAIL)
    try {
      await program.methods
        .withdraw(new anchor.BN(1_000_000))
        .accounts({
          vault: fakeVault.publicKey,  //  Fake PDA
          authority: attacker.publicKey,
        })
        .signers([attacker])
        .rpc();
      
      expect.fail("Should have rejected fake PDA");
    } catch (err) {
      expect(err.toString()).to.include("ConstraintSeeds");
      console.log(" PROTECTED! Fake PDA rejected");
    }
  });
  
  it("Accepts correct PDA", async () => {
    const user = anchor.web3.Keypair.generate();
    
    const [vaultPDA, bump] = await PublicKey.findProgramAddress(
      [Buffer.from("vault"), user.publicKey.toBuffer()],
      program.programId
    );
    
    await program.methods
      .initialize()
      .accounts({
        vault: vaultPDA,
        authority: user.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([user])
      .rpc();
    
    await program.methods
      .deposit(new anchor.BN(1_000_000))
      .accounts({
        vault: vaultPDA,
        authority: user.publicKey,
      })
      .signers([user])
      .rpc();
    
    // Should work with correct PDA
    await program.methods
      .withdraw(new anchor.BN(500_000))
      .accounts({
        vault: vaultPDA,  //  Correct PDA
        authority: user.publicKey,
      })
      .signers([user])
      .rpc();
    
    const vaultAccount = await program.account.vault.fetch(vaultPDA);
    expect(vaultAccount.balance.toNumber()).to.equal(500_000);
    console.log(" Correct PDA accepted and processed");
  });
});
```

---

##  Common Mistakes

### Mistake #1: Not Validating Seeds
```rust
//  WRONG
#[account(mut)]
pub vault: Account<'info, Vault>,

// Anyone can pass any Vault account

//  CORRECT
#[account(
    mut,
    seeds = [b"vault", authority.key().as_ref()],
    bump = vault.bump,
)]
pub vault: Account<'info, Vault>,
```

### Mistake #2: Not Storing Bump
```rust
//  WRONG
#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    // Missing bump!
}

//  CORRECT
#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8,  // Store it!
}
```

### Mistake #3: Inconsistent Seeds
```rust
//  WRONG - Seeds differ between init and use
// Initialize:
seeds = [b"vault", user.key().as_ref()]

// Later:
seeds = [b"storage", user.key().as_ref()]  // Different prefix!

//  CORRECT - Seeds must match exactly
seeds = [b"vault", user.key().as_ref()]  // Same everywhere
```

### Mistake #4: Recalculating Bump
```rust
//  EXPENSIVE
let (pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref()],
    program_id,
);
// find_program_address tries bumps 255->0 until valid

//  EFFICIENT
// Use stored bump (one calculation)
seeds = [b"vault", user.key().as_ref()],
bump = vault.bump,
```

---

##  Prevention Checklist

### For Every PDA Account

- [ ] Added `seeds` constraint matching initialization
- [ ] Added `bump` constraint using stored value
- [ ] Stored bump in account during `init`
- [ ] Seeds are identical in init and usage
- [ ] All seeds are validated (not just some)
- [ ] Tested with fake PDAs to verify rejection
- [ ] Seeds are deterministic and predictable

### Code Review
```bash
# Find PDAs without seeds validation
grep -r "#\[account(.*\]" programs/ | grep -v "seeds\|bump"

# Review each result for proper PDA validation
```

### Seed Design Patterns
```rust
// User vault: One per user
seeds = [b"vault", user.key().as_ref()]

// Token metadata: One per mint
seeds = [b"metadata", mint.key().as_ref()]

// Escrow: Unique per trade
seeds = [
    b"escrow",
    seller.key().as_ref(),
    buyer.key().as_ref(),
    nft.key().as_ref()
]

// Game character: One per player + ID
seeds = [
    b"character",
    player.key().as_ref(),
    &character_id.to_le_bytes()
]
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
pda-validation-vulnerable
  ✓ EXPLOIT: Accepts fake PDA (1523ms)
   EXPLOIT SUCCESSFUL! Withdrew from fake vault
```

### Secure Version
```bash
cd ../secure
anchor build
anchor test
```

**Expected Output:**
```
pda-validation-secure
  ✓ PROTECTED: Rejects fake PDA (1234ms)
   PROTECTED! Fake PDA rejected
  ✓ Accepts correct PDA (987ms)
```

---

##  Key Takeaways

1. **PDAs must have seeds and bump validation** - Never skip this
2. **Store the bump in your account** - Don't recalculate
3. **Use canonical bumps** - From `find_program_address`
4. **Seeds must be identical** - Init and usage must match
5. **Test with fake PDAs** - Verify they're rejected
6. **PDAs are fundamental to Solana** - Master this pattern

### The Simple Fix
```rust
// Change this:
#[account(mut)]
pub vault: Account<'info, Vault>,

// To this:
#[account(
    mut,
    seeds = [b"vault", authority.key().as_ref()],
    bump = vault.bump,
)]
pub vault: Account<'info, Vault>,
```

---

##  Additional Resources

- [Solana PDAs Explained](https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses)
- [Anchor PDA Constraints](https://www.anchor-lang.com/docs/pdas)
- [PDA Security Best Practices](https://book.anchor-lang.com/anchor_in_depth/PDAs.html)
- [Sealevel Attacks - PDA Sharing](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/4-pda-sharing)

---

