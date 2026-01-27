use anchor_lang::prelude::*;

declare_id!("Secu222222222222222222222222222222222222222");

#[program]
pub mod missing_signer_secure {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.bump = ctx.bumps.vault;
        msg!("Vault initialized for authority: {}", vault.authority);
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.user.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;
        
        vault.balance = vault.balance.checked_add(amount).unwrap();
        msg!("Deposited {} lamports", amount);
        Ok(())
    }

    ///  SECURE: Proper signature verification!
    pub fn withdraw(ctx: Context<SecureWithdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // This check is meaningful because authority is Signer
        require!(
            vault.authority == ctx.accounts.authority.key(),
            ErrorCode::Unauthorized
        );
        
        require!(vault.balance >= amount, ErrorCode::InsufficientFunds);
        
        let authority_key = vault.authority;
        let seeds = &[
            b"vault",
            authority_key.as_ref(),
            &[vault.bump],
        ];
        let signer_seeds = &[&seeds[..]];
        
        let cpi_context = CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.user.to_account_info(),
            },
            signer_seeds,
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;
        
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        msg!(" Securely withdrew {} lamports", amount);
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
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    /// CHECK: Destination account
    #[account(mut)]
    pub user: AccountInfo<'info>,
    /// FIX: Changed to Signer<'info>!
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized: Authority mismatch")]
    Unauthorized,
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
}