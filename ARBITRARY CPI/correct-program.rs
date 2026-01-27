use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer as SplTransfer};

declare_id!("CPI5ecur22222222222222222222222222222222222");

//  Whitelist of allowed programs
pub const ALLOWED_PROGRAMS: &[Pubkey] = &[
    // Add known good programs here
    anchor_spl::token::ID,
];

#[program]
pub mod arbitrary_cpi_secure {
    use super::*;

    ///  SECURE: Only calls validated Token program
    pub fn execute_token_transfer(
        ctx: Context<SecureTokenTransfer>,
        amount: u64,
    ) -> Result<()> {
        //  token_program is validated by Program<'info, Token>
        let cpi_accounts = SplTransfer {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        
        token::transfer(cpi_ctx, amount)?;
        
        msg!(" Executed CPI to validated Token program");
        Ok(())
    }

    ///  SECURE: Validates program against whitelist
    pub fn call_whitelisted_program(
        ctx: Context<CallWhitelisted>,
    ) -> Result<()> {
        //  Validate program is in whitelist
        require!(
            ALLOWED_PROGRAMS.contains(&ctx.accounts.target_program.key()),
            ErrorCode::UnauthorizedProgram
        );
        
        msg!(" Program validated against whitelist");
        Ok(())
    }

    ///  SECURE: Uses System program (known program)
    pub fn transfer_sol(
        ctx: Context<TransferSol>,
        amount: u64,
    ) -> Result<()> {
        //  system_program is validated by Program<'info, System>
        let cpi_accounts = anchor_lang::system_program::Transfer {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.system_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        
        anchor_lang::system_program::transfer(cpi_ctx, amount)?;
        
        msg!(" Transferred SOL via System program");
        Ok(())
    }
}

///  SECURE: Uses Program<'info, Token>
#[derive(Accounts)]
pub struct SecureTokenTransfer<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    ///  FIX: Program<'info, Token> validates program ID
    pub token_program: Program<'info, Token>,
}

///  SECURE: Validates against whitelist
#[derive(Accounts)]
pub struct CallWhitelisted<'info> {
    pub authority: Signer<'info>,
    /// CHECK: Validated against whitelist in instruction
    pub target_program: AccountInfo<'info>,
}

///  SECURE: Uses Program<'info, System>
#[derive(Accounts)]
pub struct TransferSol<'info> {
    #[account(mut)]
    pub from: Signer<'info>,
    /// CHECK: Destination
    #[account(mut)]
    pub to: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized program")]
    UnauthorizedProgram,
}