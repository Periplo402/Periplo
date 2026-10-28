#![no_std]

//! `AgentSmartAccount`: Phase 6b's real OpenZeppelin `stellar-accounts`
//! integration: a smart account for an agent's key, scoped so it can only
//! ever authorize calls to one specific contract (the deployed
//! `UptoSettlement` instance), never anything else.
//!
//! Built directly on `stellar_accounts::smart_account` (MIT,
//! `OpenZeppelin/stellar-contracts`), adapted from that crate's own
//! `multisig-smart-account` example: same `SmartAccount`/
//! `CustomAccountInterface` wiring, one `ContextRule` instead of many, a
//! single `Signer::Delegated` instead of a threshold policy (this contract
//! isn't a multisig, it's a single-key agent account), and no
//! `ExecutionEntryPoint`/`Upgradeable` (this account never initiates calls
//! on its own behalf and isn't upgradeable, so both would be unused
//! surface area).
//!
//! ## `Signer::Delegated`: back after `Signer::External` was ruled out too
//!
//! The original build used `Signer::Delegated(agent_key)`; every real
//! transaction trapped inside `__check_auth` (`UnreachableCodeReached`,
//! `OpenZeppelin/stellar-contracts#839`). A full retry with
//! `Signer::External` (a direct signature check against a deployed
//! `Verifier`, no nested entry) hit the identical trap, ruling out the
//! signer type itself as the differentiator; `#863` (closing `#839`) then
//! explained the real cause: Soroban's recording-mode simulation never
//! invokes `__check_auth`'s body, so a `Delegated` signer's nested
//! `require_auth_for_args` call can't be discovered ahead of time and has
//! to be hand-constructed. Once that was understood, a single-context
//! `Delegated` call settled for real on testnet; the two-context case
//! (this contract's actual shape, settle + its nested transfer) still
//! failed with a typed `Error(Contract, #3002)`
//! (`SmartAccountError::UnvalidatedContext`). `OpenZeppelin/stellar-contracts#868`
//! (`stellar-accounts` 0.8.0) replaced the raw-digest nested-entry argument
//! with a structured `AuthDigestPreimage { account, signature_payload,
//! context_rule_ids }`, confirming the old raw-digest shape as a
//! known-wrong pattern, but shipped no multi-`ContextRule` delegate test
//! of its own. This build is the retry that pin unblocks: back to
//! `Signer::Delegated`, the nested entry now carrying `AuthDigestPreimage`
//! instead of a raw digest. See `docs/DEFERRED.md`'s Phase 6b section for
//! the full history and this retry's real, on-chain result.
//!
//! ## Why `CallContract`, not `Default`
//!
//! `ContextRuleType::CallContract(upto_settlement_address)` is what makes
//! "an agent key that can only spend through the settlement contract" a
//! real, enforced property rather than a naming convention: `__check_auth`
//! rejects any authorization request whose `Context` targets a different
//! contract, regardless of what the agent's own key would otherwise sign.
//! `ContextRuleType::Default` (the shape OpenZeppelin's own example uses)
//! would authorize the agent's key for *any* contract call, which is
//! exactly the unscoped blast radius this contract exists to avoid.
//!
//! ## Why there are two context rules, not one
//!
//! `UptoSettlement::settle` pulls the buyer's tokens with a direct SEP-41
//! `transfer(&authorization.from, &this, &authorization.max_amount)`, not
//! an `approve`/`transfer_from` allowance (see that module's own doc for
//! why `upto` can't use an allowance). A plain `transfer` requires its own
//! `from.require_auth_for_args(...)`, so a real `settle()` call presents
//! this account's `__check_auth` with *two* contexts in one invocation:
//! the top-level call into `upto_settlement`, and the nested call into the
//! asset contract itself. Each needs its own matching `ContextRuleType::
//! CallContract`, so the constructor installs one rule per contract,
//! sharing the same signer and covering nothing else.
//!
//! ## Why the reserved budget lives in `UptoSettlement`, not here
//!
//! See `contracts/upto-settlement/src/budget.rs`'s module doc: the stock
//! `stellar_accounts::policies::spending_limit` policy reads the amount
//! straight out of the `Context` a `settle` call presents, and that
//! `Context`'s args are `(authorization,)` only, never `actual_amount`,
//! by design, the whole point of `require_auth_for_args` restricted to that
//! tuple is keeping the real charge outside what gets signed. No policy
//! attached at this layer can ever see the number a budget actually needs
//! to reconcile against, so this contract deliberately carries no policy at
//! all; budget enforcement is `UptoSettlement`'s own responsibility,
//! reconciled at the one place in the call graph where `actual_amount` is
//! genuinely known.

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    Address, BytesN, Env, Map, String, Val, Vec,
};
use stellar_accounts::smart_account::{
    self, AuthDigestPreimage, AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccount,
    SmartAccountError,
};

#[contract]
pub struct AgentSmartAccount;

#[contractimpl]
impl AgentSmartAccount {
    /// Creates the account with exactly two context rules: authorize calls
    /// to `upto_settlement`, and authorize the SEP-41 `transfer` call
    /// `settle` makes on `asset` to pull the buyer's funds. Both delegated
    /// to `agent_key`, a classic G-account authenticated through
    /// `require_auth_for_args((preimage,))` on a hand-constructed nested
    /// entry (`stellar-accounts` 0.8.0's `AuthDigestPreimage`, replacing
    /// the raw-digest construction that trapped before #868/#863; see
    /// `docs/DEFERRED.md`'s Phase 6b section for why `Signer::Delegated`
    /// rather than `Signer::External` for this retry).
    pub fn __constructor(
        e: &Env,
        agent_key: Address,
        upto_settlement: Address,
        asset: Address,
    ) {
        let signer = Signer::Delegated(agent_key);
        smart_account::add_context_rule(
            e,
            &ContextRuleType::CallContract(upto_settlement),
            &String::from_str(e, "upto-settlement-only"),
            None,
            &Vec::from_array(e, [signer.clone()]),
            &soroban_sdk::Map::new(e),
        );
        smart_account::add_context_rule(
            e,
            &ContextRuleType::CallContract(asset),
            &String::from_str(e, "asset-transfer-only"),
            None,
            &Vec::from_array(e, [signer]),
            &soroban_sdk::Map::new(e),
        );
    }
}

#[contractimpl]
impl CustomAccountInterface for AgentSmartAccount {
    type Error = SmartAccountError;
    type Signature = AuthPayload;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        smart_account::do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)
    }
}

#[contractimpl(contracttrait)]
impl SmartAccount for AgentSmartAccount {}

mod test;
