use anchor_lang::prelude::*;

declare_id!("PDA5ecur22222222222222222222222222222222222");

#[program]
pub mod pda_validation_secure {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.bump = ctx.bumps.vault;
        msg!("Vault initialized");
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).unwrap();
        msg!("Deposited: {}", amount);
        Ok(())
    }

    ///  SECURE: PDA seeds validated automatically
    pub fn withdraw(ctx: Context<SecureWithdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        //  seeds constraint guarantees this is the CORRECT PDA
        // Attacker cannot pass fake vault
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        msg!(" Withdrew from validated PDA: {}", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

///  SECURE: seeds and bump constraints validate PDA
#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    ///  FIX: Added seeds and bump constraints
    /// Anchor now validates the PDA derivation matches
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8,
}