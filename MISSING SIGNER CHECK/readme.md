# Missing Signer Check Vulnerability

##  Overview

**Severity:**  Critical  
**Difficulty:** Easy  
**Real-World Impact:** Wormhole Bridge Hack ($320M)

The missing signer check is one of the most common and dangerous vulnerabilities in Solana programs. It occurs when a program fails to verify that an account actually signed a transaction, allowing attackers to impersonate any account.

---

##  The Vulnerability

### What Goes Wrong

When you use `AccountInfo<'info>` instead of `Signer<'info>` for authority accounts, Anchor does not verify signatures. An attacker can:

1. Find a vault or protected resource
2. Call restricted functions with the owner's public key
3. Execute unauthorized actions **without the owner's private key**

### Vulnerable Code Pattern
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub user: SystemAccount<'info>,
    
    ///  VULNERABLE: No signature verification
    pub authority: AccountInfo<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    //  This check is meaningless because authority didn't sign!
    require!(
        vault.authority == ctx.accounts.authority.key(),
        ErrorCode::Unauthorized
    );
    
    // Transfer happens anyway
    transfer_from_vault(ctx, amount)?;
    Ok(())
}
```

### Why It's Dangerous
```
Normal Transaction:
User → Signs with private key → Program checks signature  → Success

Exploited Transaction:
Attacker → Uses victim's PUBLIC key → Program SKIPS signature check  → Success (Unauthorized!)
```

**The Problem:**
- Public keys are not secret (anyone can know your public key)
- Signatures prove you have the private key (only you can create)
- Using `AccountInfo` means NO signature verification

---

##  The Fix

### Secure Code Pattern
```rust
#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub user: SystemAccount<'info>,
    
    ///  SECURE: Enforces signature verification
    pub authority: Signer<'info>,
}

pub fn withdraw(ctx: Context<SecureWithdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    //  Now this check has meaning because authority is Signer
    require!(
        vault.authority == ctx.accounts.authority.key(),
        ErrorCode::Unauthorized
    );
    
    transfer_from_vault(ctx, amount)?;
    Ok(())
}
```

### What Changed?

| Vulnerable | Secure | What It Does |
|-----------|---------|--------------|
| `AccountInfo<'info>` | `Signer<'info>` | Automatically checks `is_signer` flag |
| No validation | Automatic validation | Returns `ProgramError::MissingRequiredSignature` if not signed |
| Any pubkey works | Must have signature | Transaction fails before instruction executes |

### What `Signer<'info>` Does Behind the Scenes
```rust
// Anchor automatically performs this check:
if !authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature.into());
}

// This happens BEFORE your instruction code runs
// Zero performance cost - just a boolean flag check
```

---

##  Real-World Example: Wormhole Bridge

**Date:** February 2, 2022  
**Loss:** $320 Million  
**Cause:** Missing signature verification

### What Happened

Wormhole is a cross-chain bridge that allows transferring assets between blockchains. The exploit happened because:

1. Wormhole's Solana program had a function that verified guardian signatures
2. The verification function could be **bypassed** by passing a fake guardian account
3. Attacker exploited this to mint 120,000 ETH on Ethereum without authorization
4. The fake account passed signature checks, allowing unauthorized bridging

### The Vulnerable Pattern (Simplified)
```rust
// Simplified version of the vulnerability
pub fn post_vaa(ctx: Context<PostVAA>, vaa: VAA) -> Result<()> {
    // Guardian set should contain valid guardian public keys
    let guardian_set = &ctx.accounts.guardian_set;
    
    //  CRITICAL BUG: guardian_set account was not validated!
    // Attacker passed a FAKE guardian_set account they created
    
    // Verify signatures against guardian set
    verify_signatures(&vaa, guardian_set)?;
    
    // If signatures valid, mint tokens
    mint_wrapped_tokens(ctx, vaa.amount)?;
    Ok(())
}

#[derive(Accounts)]
pub struct PostVAA<'info> {
    /// CHECK:  Should validate this is the REAL guardian set!
    pub guardian_set: AccountInfo<'info>,
    // ...
}
```

### The Exploit

1. Attacker created a **fake guardian_set account**
2. Filled it with public keys they control
3. Signed a fake message with their own keys
4. Passed the fake guardian_set to the program
5. Program verified signatures against FAKE guardians 
6. Minted 120,000 ETH (~$320M) without authorization

### The Fix Needed
```rust
#[derive(Accounts)]
pub struct PostVAA<'info> {
    ///  Validate this is owned by Wormhole program
    #[account(owner = wormhole::ID)]
    pub guardian_set: Account<'info, GuardianSet>,
    
    ///  AND validate seeds/bump if it's a PDA
    #[account(
        seeds = [b"GuardianSet", &guardian_set_index.to_le_bytes()],
        bump
    )]
    pub guardian_set: Account<'info, GuardianSet>,
}
```

### Lessons Learned

- Always validate **both** account ownership AND signature status
- Use `Signer<'info>` for any account that must authorize an action
- Test with malicious accounts and missing signatures
- Security audits must include signature verification checks

---

##  Testing the Vulnerability

### Exploit Test (Vulnerable Version)
```typescript
import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";

describe("missing-signer-vulnerable", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.MissingSignerVulnerable;

  it("EXPLOIT: Attacker drains vault without authority signature", async () => {
    // Setup: Create victim and attacker
    const victim = anchor.web3.Keypair.generate();
    const attacker = anchor.web3.Keypair.generate();
    
    // Airdrop SOL to victim
    await provider.connection.requestAirdrop(
      victim.publicKey,
      10 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Find vault PDA for victim
    const [vaultPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), victim.publicKey.toBuffer()],
      program.programId
    );
    
    // Victim initializes vault
    await program.methods
      .initialize()
      .accounts({
        vault: vaultPDA,
        authority: victim.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([victim])
      .rpc();
    
    // Victim deposits 5 SOL
    await program.methods
      .deposit(new anchor.BN(5 * anchor.web3.LAMPORTS_PER_SOL))
      .accounts({
        vault: vaultPDA,
        user: victim.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([victim])
      .rpc();
    
    console.log(" Vault initialized with 5 SOL");
    
    // EXPLOIT: Attacker withdraws WITHOUT victim signature!
    const attackerBalanceBefore = await provider.connection.getBalance(
      attacker.publicKey
    );
    
    console.log(" Attempting exploit...");
    
    await program.methods
      .withdraw(new anchor.BN(1 * anchor.web3.LAMPORTS_PER_SOL))
      .accounts({
        vault: vaultPDA,
        user: attacker.publicKey,
        authority: victim.publicKey,  //  Victim's key, NO signature!
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([attacker])  //  Only attacker signs
      .rpc();
    
    const attackerBalanceAfter = await provider.connection.getBalance(
      attacker.publicKey
    );
    
    // Verify exploit worked
    expect(attackerBalanceAfter).to.be.greaterThan(attackerBalanceBefore);
    console.log(" EXPLOIT SUCCESSFUL! Attacker stole funds without victim's signature!");
  });
});
```

### Security Test (Secure Version)
```typescript
describe("missing-signer-secure", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.MissingSignerSecure;

  it("PROTECTED: Rejects withdrawal without signature", async () => {
    const victim = anchor.web3.Keypair.generate();
    const attacker = anchor.web3.Keypair.generate();
    
    // Setup (same as vulnerable test)
    await provider.connection.requestAirdrop(
      victim.publicKey,
      10 * anchor.web3.LAMPORTS_PER_SOL
    );
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const [vaultPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), victim.publicKey.toBuffer()],
      program.programId
    );
    
    await program.methods
      .initialize()
      .accounts({
        vault: vaultPDA,
        authority: victim.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([victim])
      .rpc();
    
    await program.methods
      .deposit(new anchor.BN(5 * anchor.web3.LAMPORTS_PER_SOL))
      .accounts({
        vault: vaultPDA,
        user: victim.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([victim])
      .rpc();
    
    // Try exploit (should FAIL)
    console.log("  Attempting exploit on secure version...");
    
    try {
      await program.methods
        .withdraw(new anchor.BN(1 * anchor.web3.LAMPORTS_PER_SOL))
        .accounts({
          vault: vaultPDA,
          user: attacker.publicKey,
          authority: victim.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();
      
      expect.fail("Should have thrown an error");
    } catch (err) {
      expect(err.toString()).to.include("Signature verification failed");
      console.log(" PROTECTED! Exploit blocked by Signer check");
    }
  });
});
```

---

##  Prevention Checklist

### Before Deployment

- [ ] All authority/owner accounts use `Signer<'info>`
- [ ] No `AccountInfo<'info>` used for authorization
- [ ] Manual `is_signer` checks present in non-Anchor code
- [ ] Tests include missing signature scenarios
- [ ] Audit confirms signature validation on all paths

### Code Review Questions

1. **Does this account need to authorize an action?**
   - If yes, is it using `Signer<'info>`?

2. **Are there alternative code paths that skip validation?**
   - Check all instruction variants

3. **What happens if this account doesn't sign?**
   - Should fail with clear error message

4. **Could an attacker pass a different public key here?**
   - Signature check prevents this

### Quick Grep Commands
```bash
# Find potentially vulnerable patterns
grep -r "pub.*authority.*AccountInfo" programs/
grep -r "pub.*owner.*AccountInfo" programs/
grep -r "pub.*signer.*AccountInfo" programs/

# Should return no results in production code
```

---

##  Running This Example

### Setup
```bash
# Navigate to vulnerable version
cd vulnerable

# Install dependencies
npm install

# Build the program
anchor build

# Run tests (shows exploit working)
anchor test
```

**Expected Output:**
```
missing-signer-vulnerable
  ✓ EXPLOIT: Attacker drains vault without authority signature (1523ms)
   EXPLOIT SUCCESSFUL! Attacker stole funds without victim's signature!
```

### Secure Version
```bash
# Navigate to secure version
cd ../secure

# Build and test
anchor build
anchor test
```

**Expected Output:**
```
missing-signer-secure
  ✓ PROTECTED: Rejects withdrawal without signature (1234ms)
   PROTECTED! Exploit blocked by Signer check
```

---

##  Key Takeaways

1. **Always use `Signer<'info>` for authority accounts** - This is non-negotiable
2. **Public keys are not secret** - Anyone can use anyone's public key
3. **Signatures prove ownership** - Only the private key holder can sign
4. **The `Signer` type is free** - Zero performance cost for maximum security
5. **This is the #1 most common vulnerability** - Check every authority account
6. **Test explicitly** - Write tests where required signers don't sign

### The One-Line Fix
```rust
// Change this:
pub authority: AccountInfo<'info>,

// To this:
pub authority: Signer<'info>,

// That's it. You're secure.
```

---

