# Solana Meme Coin Technical Assessment

## 1. Solana Fundamentals

### Accounts, programs, and PDAs

- **Accounts** are the persistent data and asset containers in Solana. Every account has an owner program, lamports, and optional data. For a meme coin, the SPL mint account stores token configuration, while an associated token account stores a wallet's balance.
- **Programs** are executable Solana accounts containing stateless instructions. The SPL Token Program creates mints and performs token transfers; the project's Anchor program would enforce presale, treasury, airdrop, or staking rules.
- **PDAs (Program Derived Addresses)** are deterministic addresses derived from seeds and a program ID. They have no private key, so the owning program can sign for them with `invoke_signed`. A treasury PDA can hold reward tokens, and a staking-position PDA such as `[b"position", user.key().as_ref()]` can hold one user's staking state.

### Why Anchor

Anchor reduces boilerplate through typed account contexts, declarative constraints, instruction handlers, generated IDLs, and structured errors and events. It makes common security checks visible in the account definition and improves client integration and testing. Native Solana development remains useful when minimizing dependencies or needing lower-level control, but it requires manually handling serialization, instruction parsing, account ownership, signer checks, and CPI safety.

### Treasury security

The treasury should use a PDA or a multisignature-controlled authority rather than an individual developer wallet. Enforce the expected mint, token-account owner, token program, and destination on every transfer. Separate mint, freeze, treasury, and administrative authorities where possible; revoke unused authorities; use multisig and transaction simulation for administration; and use a timelock for material changes.

The program should apply spending limits, pause/emergency controls, replay-safe state transitions, checked arithmetic, and complete events. Operational controls should include hardware-wallet custody, least privilege, key rotation, monitoring, incident response, and independent audit review. Solana-specific risks include accepting accounts owned by the wrong program, unchecked CPIs, upgrade-authority compromise, account reinitialization, and rent/account lifecycle mistakes.

## 2. Architecture Review

### Strengths

SPL Token provides a standard, wallet-compatible token model. Solana offers low fees and high throughput, while Anchor can provide typed account validation and a generated client interface. Separating token custody and application logic is a sound starting point.

### Limitations

Wallet connection and transfers alone do not define token economics, treasury authority, supply controls, allocation limits, or recovery procedures. The architecture needs a clear authority model, validated token-account relationships, transaction error handling, transaction-status confirmation, observability, and a test environment. It also needs documented upgrade, pause, and migration procedures.

### Security concerns

The main risks are confused-deputy transfers, wrong-mint or wrong-owner token accounts, unchecked authorities, accidental use of a user signer as a treasury authority, arbitrary CPI programs, arithmetic overflow, duplicate claims, insufficient replay protection, and compromised upgrade keys. Client-side validation is not sufficient; all security-critical checks must be on-chain.

### Production requirements

- Pin the program ID and declare all authorities explicitly.
- Use PDA-controlled treasury accounts and verified signer seeds.
- Add Anchor constraints for token program, mint, source owner, destination owner, and authority.
- Define supply, mint, freeze, allocation, and emergency-pause policies.
- Add events, structured errors, rate/amount limits, and checked arithmetic.
- Add integration tests, fuzz/property tests for accounting, and negative authorization tests.
- Add frontend transaction simulation, confirmation handling, RPC failover, monitoring, multisig operations, deployment verification, and an upgrade-authority policy.
- Obtain an independent security review before mainnet launch.

### Recommended next phase

First stabilize the on-chain core: initialize the mint and treasury, define PDA authorities, implement one safe transfer path, and test it thoroughly on localnet/devnet. Then add presale or staking as separate state machines with explicit caps and accounting invariants. Only after those invariants are tested should the frontend and token distribution workflow be expanded.

## 3. Code Review: `transfer_rewards`

The handler delegates to the SPL Token Program, but the safety of the operation depends entirely on `TransferRewards` and `transfer_context()`. The snippet itself does not prove that the source, destination, mint, authority, and token program are correctly related.

### Missing validations and risks

- The source account must be owned by the SPL Token Program and be mutable.
- The destination must be mutable and use the same mint as the source.
- The source must be controlled by the expected treasury PDA or authorized reward authority.
- The destination owner must be the intended recipient, not an arbitrary account.
- The mint must be the configured project mint.
- The token program should be constrained to the expected SPL Token Program, or Token-2022 support should be deliberate and explicit.
- `amount` must be non-zero where zero-value transfers are not meaningful and must respect any reward or per-call cap.
- The caller must be authorized; a generic signer check is not enough if the authority should be a PDA or administrator.
- The instruction needs protection against duplicate claims, usually through a recipient claim/state account or a monotonically increasing accounting record.
- Arithmetic used to calculate `amount` must use checked operations before this transfer.

Without these checks, an attacker could redirect rewards, use a wrong mint, drain a treasury through repeated calls, or exploit a confused authority/account relationship. SPL Token will reject some malformed transfers, but it cannot enforce the application's business rules.

### Safer Anchor account shape

The following is a focused account/CPI sketch, not a complete standalone program. A production implementation must add a claim or staking-position account and authorize the caller before transferring funds. Without that state transition, even a PDA-signed transfer can be called repeatedly by anyone.

```rust
#[derive(Accounts)]
#[instruction(amount: u64)]
pub struct TransferRewards<'info> {
    #[account(
        mut,
        token::mint = reward_mint,
        token::authority = treasury_authority,
    )]
    pub treasury: Account<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = reward_mint,
        token::authority = recipient,
    )]
    pub recipient_token_account: Account<'info, TokenAccount>,

    pub reward_mint: Account<'info, Mint>,
    pub recipient: UncheckedAccount<'info>,

    // A production version should constrain this PDA to the recipient and
    // mark it as claimed or reduce its pending reward before the CPI.
    #[account(
        mut,
        seeds = [b"claim", recipient.key().as_ref()],
        bump,
    )]
    pub claim: Account<'info, Claim>,

    #[account(
        seeds = [b"treasury-authority"],
        bump,
    )]
    /// CHECK: PDA authority is verified by the seeds and used only for the token CPI.
    pub treasury_authority: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
}

pub fn transfer_rewards(ctx: Context<TransferRewards>, amount: u64) -> Result<()> {
    require!(
        ctx.accounts.claim.recipient == ctx.accounts.recipient.key(),
        ErrorCode::InvalidClaim
    );
    require!(!ctx.accounts.claim.paid, ErrorCode::AlreadyClaimed);
    require!(amount > 0, ErrorCode::InvalidAmount);
    require!(amount <= MAX_REWARD_PER_CLAIM, ErrorCode::RewardLimitExceeded);

    ctx.accounts.claim.paid = true;

    let bump = ctx.bumps.treasury_authority;
    let signer_seeds: &[&[u8]] = &[b"treasury-authority", &[bump]];

    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.treasury.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.treasury_authority.to_account_info(),
            },
            &[signer_seeds],
        ),
        amount,
    )?;

    Ok(())
}
```

In production, the recipient should normally be a typed signer or be bound to a previously initialized staking/claim PDA. `UncheckedAccount` should be used only where the PDA is fully constrained and documented. The exact account layout depends on whether rewards are pull-based, operator-triggered, or distributed by a crank. The example also requires definitions for `Claim`, `MAX_REWARD_PER_CLAIM`, and the listed error variants; these are omitted to keep the review focused.

### Tests

Test successful transfer and exact balances. Test zero amount, reward-cap violations, insufficient treasury balance, wrong mint, wrong source authority, wrong destination owner, wrong token program, unauthorized caller, invalid PDA seeds, duplicate claim, and repeated claims. Also test boundary timestamps and reward arithmetic using values that would overflow if unchecked. Verify expected events and ensure failed transactions leave all accounting unchanged.

## 4. Staking Design

Use a global `Pool` PDA containing the staking mint, reward mint, reward-vault PDA, total staked amount, reward rate or emission schedule, accumulated reward-per-share, last update time, pause flag, and administrator/multisig authority. Each user gets a `StakePosition` PDA containing the owner, amount staked, reward debt or checkpoint, pending rewards, and an optional lock end time. User stake and reward token accounts must be constrained to their corresponding mints and owners.

Use integer fixed-point accounting, for example an accumulated reward-per-share value with a large precision factor. On every stake, unstake, or claim, update the pool to the current slot/time, calculate the user's pending reward from their previous checkpoint, then update the checkpoint before changing the stake amount. Cap emissions, use checked arithmetic, and define behavior when the pool is empty or paused.

Rewards should be funded in advance in a PDA-controlled reward vault. Users should claim through a pull-based instruction, with the PDA signing the SPL Token CPI. This avoids trusting an operator to choose recipients and makes each claim auditable. Unstake rules, lockups, early penalties, and end-of-program behavior must be explicit.

Security controls include strict PDA and mint constraints, authorized parameter changes, delayed or multisig administration, pause and recovery procedures, no arbitrary CPI programs, protection against double claims and reinitialization, and tests for rounding, overflow, zero-stake periods, partial withdrawals, and reward-vault exhaustion.

## Submission Note

The Solidity files in this folder are legacy Ethereum ERC-20 examples and are not part of this Solana/Anchor implementation. They should not be presented as the solution unless the employer separately requested an Ethereum contract review.
