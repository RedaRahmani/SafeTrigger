// Anchor / Solana macros emit cfg checks and use deprecated APIs that our
// toolchain warns about. These are NOT our code — suppress only these
// known macro-generated warnings so that clippy -D warnings passes.
#![allow(unexpected_cfgs)]
#![allow(deprecated)]

use anchor_lang::prelude::*;

// Placeholder; will be replaced via `anchor keys sync` once a keypair exists.
declare_id!("2ys3Ma4PQeQTXPp7wDzhUw6dbgFLmdDWuAWXBmeourqn");

#[program]
pub mod test_oracle {
    use super::*;

    pub fn init_feed(ctx: Context<InitFeed>, price: u64, last_updated_slot: u64) -> Result<()> {
        let feed = &mut ctx.accounts.feed;
        feed.authority = ctx.accounts.authority.key();
        feed.price = price;
        feed.last_updated_slot = last_updated_slot;
        Ok(())
    }

    pub fn set_feed(ctx: Context<SetFeed>, price: u64, last_updated_slot: u64) -> Result<()> {
        let feed = &mut ctx.accounts.feed;
        feed.price = price;
        feed.last_updated_slot = last_updated_slot;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitFeed<'info> {
    #[account(init, payer = authority, space = PriceFeed::SPACE)]
    pub feed: Account<'info, PriceFeed>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetFeed<'info> {
    #[account(mut, has_one = authority)]
    pub feed: Account<'info, PriceFeed>,

    pub authority: Signer<'info>,
}

#[account]
#[derive(Debug)]
pub struct PriceFeed {
    pub authority: Pubkey,
    /// Price in PRICE_PRECISION (1e6) units.
    pub price: u64,
    /// Slot of last update.
    pub last_updated_slot: u64,
}

impl PriceFeed {
    pub const SPACE: usize = 8 + 32 + 8 + 8;
}
