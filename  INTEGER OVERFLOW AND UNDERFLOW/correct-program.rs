use anchor_lang::prelude::*;

declare_id!("Int5ecur22222222222222222222222222222222222");

#[program]
pub mod integer_overflow_secure {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.authority = ctx.accounts.authority.key();
        user.points = 0;
        user.tokens = 0;
        Ok(())
    }

    ///   SECURE: Uses checked_add
    pub fn add_points(ctx: Context<UpdateUser>, points: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        
        //   Returns None on overflow, we handle it
        user.points = user.points
            .checked_add(points)
            .ok_or(ErrorCode::Overflow)?;
        
        msg!("  Added points safely: {}", user.points);
        Ok(())
    }

    ///   SECURE: Uses checked_sub
    pub fn remove_points(ctx: Context<UpdateUser>, points: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        
        //   Returns None on underflow
        user.points = user.points
            .checked_sub(points)
            .ok_or(ErrorCode::InsufficientPoints)?;
        
        msg!("  Removed points safely: {}", user.points);
        Ok(())
    }

    ///   SECURE: Uses checked_mul
    pub fn calculate_tokens(ctx: Context<UpdateUser>, multiplier: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        
        //   Returns None on overflow
        user.tokens = user.points
            .checked_mul(multiplier)
            .ok_or(ErrorCode::Overflow)?;
        
        msg!("  Calculated tokens safely: {}", user.tokens);
        Ok(())
    }

    ///   SECURE: Uses checked_div
    pub fn calculate_average(ctx: Context<UpdateUser>, divisor: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        
        //   Returns None on division by zero
        user.tokens = user.points
            .checked_div(divisor)
            .ok_or(ErrorCode::DivisionByZero)?;
        
        msg!("  Average calculated safely: {}", user.tokens);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + User::INIT_SPACE)]
    pub user: Account<'info, User>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateUser<'info> {
    #[account(mut, has_one = authority)]
    pub user: Account<'info, User>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct User {
    pub authority: Pubkey,
    pub points: u64,
    pub tokens: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Insufficient points")]
    InsufficientPoints,
    #[msg("Division by zero")]
    DivisionByZero,
}