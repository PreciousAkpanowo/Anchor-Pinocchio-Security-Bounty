use anchor_lang::prelude::*;

declare_id!("PDAvu1n11111111111111111111111111111111111");

#[program]
pub mod pda_validation_vulnerable {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        msg!("Vault initialized");
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).unwrap();
        msg!("Deposited: {}", amount);
        Ok(())
    }

    ///  VULNERABLE: No PDA seed validation!
    /// Attacker can pass ANY vault account
    pub fn withdraw(ctx: Context<VulnerableWithdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        //  Only checks authority match
        // But attacker created their OWN vault with themselves as authority!
        require!(
            vault.authority == ctx.accounts.authority.key(),
            ErrorCode::Unauthorized
        );
        
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        msg!(" Withdrew from unvalidated PDA: {}", amount);
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
        seeds = [b"vault", vault.authority.as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

///  VULNERABLE: No seeds constraint!
#[derive(Accounts)]
pub struct VulnerableWithdraw<'info> {
    ///  BUG: Should have seeds and bump constraints
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}