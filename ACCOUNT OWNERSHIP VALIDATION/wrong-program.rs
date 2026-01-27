use anchor_lang::prelude::*;

declare_id!("Acc0wn111111111111111111111111111111111111");

#[program]
pub mod account_ownership_vulnerable {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, initial_balance: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        user_account.owner = ctx.accounts.authority.key();
        user_account.balance = initial_balance;
        user_account.points = 0;
        msg!("User account initialized");
        Ok(())
    }

    ///  VULNERABLE: No ownership check on user_account!
    /// Attacker can pass ANY account (even one they created)
    pub fn add_points(ctx: Context<AddPoints>, points: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        
        //  This uses AccountInfo, so ANY account can be passed
        // Attacker could pass an account from a different program!
        user_account.points = user_account.points.checked_add(points).unwrap();
        
        msg!(" Added {} points without ownership check!", points);
        Ok(())
    }

    ///  VULNERABLE: Processes data from unverified account
    pub fn claim_reward(ctx: Context<ClaimReward>) -> Result<()> {
        let user_account = &ctx.accounts.user_account;
        
        //  Reading data from potentially fake account
        let reward = user_account.points / 100;
        
        msg!(" Claiming {} tokens based on unverified points", reward);
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

///  VULNERABLE STRUCT: Uses AccountInfo instead of Account<T>
#[derive(Accounts)]
pub struct AddPoints<'info> {
    /// BUG: Should be Account<'info, UserAccount>
    /// CHECK: Deliberately vulnerable!
    #[account(mut)]
    pub user_account: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimReward<'info> {
    /// BUG: No ownership validation
    /// CHECK: Deliberately vulnerable!
    pub user_account: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub points: u64,
}