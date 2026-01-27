use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke, instruction::Instruction, instruction::AccountMeta};

declare_id!("CPIvu1n11111111111111111111111111111111111");

#[program]
pub mod arbitrary_cpi_vulnerable {
    use super::*;

    ///  VULNERABLE: Accepts ANY program for CPI
    /// Attacker can pass malicious program
    pub fn execute_transfer(
        ctx: Context<VulnerableTransfer>,
        amount: u64,
    ) -> Result<()> {
        //  target_program could be ANYTHING!
        // Attacker passes their malicious program here
        let ix = Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.from.key(), true),
                AccountMeta::new(ctx.accounts.to.key(), false),
            ],
            data: amount.to_le_bytes().to_vec(),
        };
        
        //  Calling unvalidated program!
        invoke(
            &ix,
            &[
                ctx.accounts.from.to_account_info(),
                ctx.accounts.to.to_account_info(),
                ctx.accounts.target_program.to_account_info(),
            ],
        )?;
        
        msg!(" Executed CPI to unvalidated program!");
        Ok(())
    }

    ///  VULNERABLE: Accepts any program_id parameter
    pub fn call_external(
        ctx: Context<CallExternal>,
        program_id: Pubkey,
    ) -> Result<()> {
        //  Using program_id from user input!
        msg!(" Calling program: {}", program_id);
        
        // Malicious CPI would happen here
        Ok(())
    }
}

///  VULNERABLE: No validation on target_program
#[derive(Accounts)]
pub struct VulnerableTransfer<'info> {
    #[account(mut)]
    pub from: Signer<'info>,
    /// CHECK: Destination
    #[account(mut)]
    pub to: AccountInfo<'info>,
    /// CHECK:  DANGEROUS - any program accepted!
    pub target_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CallExternal<'info> {
    pub authority: Signer<'info>,
}