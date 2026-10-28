#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{symbol_short, testutils::Address as _, vec, Bytes, Map};

/// `agent-smart-account` and `upto-settlement` cannot share a Rust `Env`
/// type in the same test binary (see `contracts/upto-settlement/src/
/// budget.rs`'s module doc), so a genuine same-process Rust cross-contract
/// test between the two is not possible with this architecture. What this
/// file proves instead: the account's own authorization decision, directly,
/// via real `__check_auth` invocations under `e.mock_all_auths()` (the
/// scoping/signer-recognition logic, not the real nested `Signer::Delegated`
/// entry construction, which only a real signed testnet transaction
/// exercises, see `apps/facilitator/scripts/agent-smart-account-settle-demo.ts`
/// and `conformance/RESULTS.md`).
fn create_signatures(e: &Env, agent_key: &Address, context_rule_id: u32) -> AuthPayload {
    let mut signers = Map::new(e);
    // Under mock_all_auths, the Delegated arm's nested require_auth_for_args
    // call is satisfied without a real signature; the empty-bytes entry
    // here only needs to exist so the signer is recognized in the map,
    // matching stellar-accounts' own convention that a Delegated signer's
    // real authorization lives in the separate nested entry, not here.
    signers.set(Signer::Delegated(agent_key.clone()), Bytes::new(e));
    AuthPayload {
        signers,
        context_rule_ids: soroban_sdk::Vec::from_array(e, [context_rule_id]),
    }
}

fn context(contract: Address, fn_name: soroban_sdk::Symbol, args: Vec<Val>) -> Context {
    Context::Contract(soroban_sdk::auth::ContractContext {
        contract,
        fn_name,
        args,
    })
}

fn digest(e: &Env) -> soroban_sdk::crypto::Hash<32> {
    e.crypto()
        .sha256(&Bytes::from_array(e, b"phase-6b-test-payload"))
}

#[test]
fn check_auth_succeeds_for_a_call_to_the_registered_contract() {
    let e = Env::default();
    e.mock_all_auths();

    let agent_key = Address::generate(&e);
    let upto_settlement = Address::generate(&e);
    let asset = Address::generate(&e);
    let account_id = e.register(
        AgentSmartAccount,
        (agent_key.clone(), upto_settlement.clone(), asset),
    );

    let rule = e.as_contract(&account_id, || smart_account::get_context_rule(&e, 0));
    assert_eq!(
        rule.context_type,
        ContextRuleType::CallContract(upto_settlement.clone())
    );

    let ctx = context(upto_settlement, symbol_short!("settle"), vec![&e]);
    let signatures = create_signatures(&e, &agent_key, rule.id);
    let payload_hash = digest(&e);

    let result: Result<(), SmartAccountError> = e.as_contract(&account_id, || {
        AgentSmartAccount::__check_auth(e.clone(), payload_hash, signatures, vec![&e, ctx])
    });
    assert!(
        result.is_ok(),
        "a call scoped to the registered contract must be authorized"
    );
}

#[test]
fn check_auth_succeeds_for_the_nested_asset_transfer_alongside_settle() {
    // A real settle() call presents __check_auth with TWO contexts in one
    // invocation (the top-level settle call, and the nested SEP-41
    // transfer()), see this module's own doc for why. Both must validate
    // together against context_rule_ids aligned by index to auth_contexts,
    // matching stellar-accounts' own do_check_auth_multiple_contexts_success
    // convention. This is exactly the shape that failed on real testnet
    // with UnvalidatedContext #3002 under the old raw-digest encoding;
    // under mock_all_auths this only proves the scoping logic, not the
    // real nested-entry construction.
    let e = Env::default();
    e.mock_all_auths();

    let agent_key = Address::generate(&e);
    let upto_settlement = Address::generate(&e);
    let asset = Address::generate(&e);
    let account_id = e.register(
        AgentSmartAccount,
        (agent_key.clone(), upto_settlement.clone(), asset.clone()),
    );

    let settle_rule = e.as_contract(&account_id, || smart_account::get_context_rule(&e, 0));
    let transfer_rule = e.as_contract(&account_id, || smart_account::get_context_rule(&e, 1));
    assert_eq!(
        transfer_rule.context_type,
        ContextRuleType::CallContract(asset.clone())
    );

    let settle_ctx = context(upto_settlement, symbol_short!("settle"), vec![&e]);
    let transfer_ctx = context(asset, symbol_short!("transfer"), vec![&e]);

    let mut signers = Map::new(&e);
    signers.set(Signer::Delegated(agent_key), Bytes::new(&e));
    let signatures = AuthPayload {
        signers,
        context_rule_ids: soroban_sdk::Vec::from_array(&e, [settle_rule.id, transfer_rule.id]),
    };
    let payload_hash = digest(&e);

    let result: Result<(), SmartAccountError> = e.as_contract(&account_id, || {
        AgentSmartAccount::__check_auth(
            e.clone(),
            payload_hash,
            signatures,
            vec![&e, settle_ctx, transfer_ctx],
        )
    });
    assert!(
        result.is_ok(),
        "both the settle call and its nested asset transfer must be authorized together"
    );
}

#[test]
fn check_auth_rejects_a_call_to_a_different_contract() {
    // The core claim of this whole contract: an agent key wrapped in this
    // account cannot authorize spending through anything except the one
    // contract its context rule names, even with a fully valid signature.
    let e = Env::default();
    e.mock_all_auths();

    let agent_key = Address::generate(&e);
    let upto_settlement = Address::generate(&e);
    let asset = Address::generate(&e);
    let account_id = e.register(
        AgentSmartAccount,
        (agent_key.clone(), upto_settlement, asset),
    );

    let rule = e.as_contract(&account_id, || smart_account::get_context_rule(&e, 0));

    let some_other_contract = Address::generate(&e);
    let ctx = context(some_other_contract, symbol_short!("transfer"), vec![&e]);
    let signatures = create_signatures(&e, &agent_key, rule.id);
    let payload_hash = digest(&e);

    // do_check_auth panics on a context/rule mismatch rather than returning
    // Err (confirmed by running this exact call without the catch first:
    // Error(Contract, #3002), a real host-level rejection, not assumed from
    // the return type alone). Caught here rather than asserted as a plain
    // Result, since this call goes straight to the contract impl function,
    // not through a generated Client's try_ wrapper that would normally
    // convert a host panic into a catchable Result.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.as_contract(&account_id, || {
            AgentSmartAccount::__check_auth(e.clone(), payload_hash, signatures, vec![&e, ctx])
        })
    }));
    assert!(
        result.is_err(),
        "a call to a contract other than the one this account is scoped to must be rejected"
    );
}

#[test]
fn check_auth_rejects_an_unrecognized_signer() {
    let e = Env::default();
    e.mock_all_auths();

    let agent_key = Address::generate(&e);
    let stranger_key = Address::generate(&e);
    let upto_settlement = Address::generate(&e);
    let asset = Address::generate(&e);
    let account_id = e.register(
        AgentSmartAccount,
        (agent_key, upto_settlement.clone(), asset),
    );

    let rule = e.as_contract(&account_id, || smart_account::get_context_rule(&e, 0));

    let ctx = context(upto_settlement, symbol_short!("settle"), vec![&e]);
    // A signature keyed to a signer the account never registered.
    let signatures = create_signatures(&e, &stranger_key, rule.id);
    let payload_hash = digest(&e);

    // See the panic-vs-Result note in check_auth_rejects_a_call_to_a_different_contract.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.as_contract(&account_id, || {
            AgentSmartAccount::__check_auth(e.clone(), payload_hash, signatures, vec![&e, ctx])
        })
    }));
    assert!(
        result.is_err(),
        "a signature from an unregistered signer must be rejected"
    );
}
