use anchor_lang::prelude::*;

declare_id!("Int0ver11111111111111111111111111111111111");

#[program]
pub mod integer_overflow_vulnerable {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.authority = ctx.accounts.authority.key();
        user.points = 0;
        user.tokens = 0;
        Ok(())
    }

    ///  VULNERABLE: Addition can overflow (wrap to 0)
    pub fn add_points(ctx: Context<UpdateUser>, points: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        
        //  If user.points = u64::MAX and points = 1
        // Result: user.points = 0 (overflow!)
        user.points = user.points + points;
        
        msg!(" Added points with unsafe arithmetic: {}", user.points);
        Ok(())
    }

    ///  VULNERABLE: Subtraction can underflow (wrap to huge number)
    pub fn remove_points(ctx: Context<UpdateUser>, points: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        
        //  If user.points = 100 and points = 200
        // Result: user.points = 18446744073709551516 (underflow!)
        user.points = user.points - points;
        
        msg!(" Removed points with unsafe arithmetic: {}", user.points);
        Ok(())
    }

    ///  VULNERABLE: Multiplication can overflow
    pub fn calculate_tokens(ctx: Context<UpdateUser>, multiplier: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        
        //  Can overflow if points * multiplier > u64::MAX
        user.tokens = user.points * multiplier;
        
        msg!(" Calculated tokens unsafely: {}", user.tokens);
        Ok(())
    }

    ///  VULNERABLE: Division by zero not checked
    pub fn calculate_average(ctx: Context<UpdateUser>, divisor: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        
        //  CRASH if divisor = 0
        user.tokens = user.points / divisor;
        
        msg!("Average: {}", user.tokens);
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