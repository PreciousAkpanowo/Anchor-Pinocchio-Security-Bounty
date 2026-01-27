use anchor_lang::prelude::*;

declare_id!("Acc5ecur22222222222222222222222222222222222");

#[program]
pub mod account_ownership_secure {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, initial_balance: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        user_account.owner = ctx.accounts.authority.key();
        user_account.balance = initial_balance;
        user_account.points = 0;
        msg!("User account initialized");
        Ok(())
    }

    ///  SECURE: Ownership automatically validated
    pub fn add_points(ctx: Context<SecureAddPoints>, points: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        
        //  Account<'info, UserAccount> ensures:
        // - Owner is this program
        // - Data deserializes correctly
        // - Discriminator matches
        user_account.points = user_account.points.checked_add(points).unwrap();
        
        msg!(" Added {} points with ownership verification", points);
        Ok(())
    }

    ///  SECURE: Only processes verified accounts
    pub fn claim_reward(ctx: Context<SecureClaimReward>) -> Result<()> {
        let user_account = &ctx.accounts.user_account;
        
        //  Safe to read - ownership verified
        let reward = user_account.points / 100;
        
        msg!(" Claiming {} tokens from verified account", reward);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + UserAccount::INIT_SPACE
    )]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

///  SECURE STRUCT: Uses Account<T> for type safety
#[derive(Accounts)]
pub struct SecureAddPoints<'info> {
    ///  FIX: Account<'info, UserAccount> validates:
    /// - owner == this program
    /// - data deserializes to UserAccount
    /// - discriminator matches
    #[account(mut, has_one = owner)]
    pub user_account: Account<'info, UserAccount>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct SecureClaimReward<'info> {
    /// FIX: Proper type validation
    #[account(has_one = owner)]
    pub user_account: Account<'info, UserAccount>,
    pub owner: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub points: u64,
}