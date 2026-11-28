use core::fmt;

/// Every failure `sorocharge-signer` can produce.
///
/// Each variant names one specific, actionable failure so a caller (or a
/// test) can tell exactly which check failed rather than pattern-matching on
/// a string. No variant collapses distinct failures into a catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SorochargeError {
    /// A strkey (`G...`, `C...`, `M...`) failed to decode into an `ScAddress`.
    InvalidAddress { strkey: String },
    /// The credential's XDR shape does not match any variant this library
    /// signs or verifies (e.g. a future `SorobanCredentialsType` arm).
    UnsupportedCredentialType,
    /// `Delegated` was constructed with no signers, which can never satisfy
    /// `__check_auth`.
    EmptyDelegateSigners,
    /// `Delegated` named the same address as a delegate signer more than
    /// once, which CAP-71-01 forbids (the host rejects the entry).
    DuplicateDelegateSigner,
    /// The entry's `valid_until_ledger` has already passed `current_ledger`.
    ExpiredEntry {
        valid_until_ledger: u32,
        current_ledger: u32,
    },
    /// The entry's own `signature_expiration_ledger` is later than the
    /// caller's `expected.valid_until_ledger` — it isn't expired, but it is
    /// valid for longer than the caller said it would accept.
    ///
    /// Returned from exactly two places, both for exactly this condition
    /// (`signature_expiration_ledger > expected.valid_until_ledger`), and
    /// each only after [`ExpiredEntry`](Self::ExpiredEntry) has been ruled
    /// out: [`verify_entry`](crate::verify_entry) and
    /// [`verify_delegated_threshold`](crate::verify_delegated_threshold).
    ExpirationExceedsAllowance {
        signature_expiration_ledger: u32,
        allowed_until_ledger: u32,
    },
    /// The entry's invocation is not a SEP-41 `transfer(from, to, amount)`
    /// call on a single contract, so there is nothing meaningful to compare
    /// its asset/payer/amount/recipient against.
    ///
    /// Returned only by [`verify_entry`](crate::verify_entry), when the
    /// entry's `root_invocation` is any of:
    ///
    /// - a node with sub-invocations, which would authorize calls beyond
    ///   the single transfer (so it is no longer "a single contract" call);
    /// - not a contract call at all (e.g. a `CreateContractHostFn`);
    /// - a contract call to a function other than exactly `transfer`;
    /// - a `transfer` call whose arguments are not exactly
    ///   `(Address, Address, I128)`.
    ///
    /// Every one of these is a property of the entry itself. Internal
    /// failures (e.g. a bug in this crate) are never reported through this
    /// variant. Transaction-level shape problems, such as a wrong operation
    /// count, belong to the x402/MPP adapters' own
    /// `UnexpectedTransactionShape` errors, not to this variant.
    UnexpectedInvocationShape,
    /// The entry's asset contract does not match `ChargeParams::asset_contract`.
    AssetMismatch,
    /// The entry's authorizing address does not match `ChargeParams::payer`.
    PayerMismatch,
    /// The entry's amount does not match `ChargeParams::amount` exactly.
    AmountMismatch,
    /// The `to` argument of the entry's SEP-41 `transfer(from, to, amount)`
    /// invocation does not match `ChargeParams::recipient`.
    ///
    /// Returned only by `verify_entry`, after the asset, payer and amount
    /// checks have already passed.
    RecipientMismatch,
    /// The entry's attached signatures do not authorize it: none verifies
    /// over the reconstructed `HashIdPreimage`, or (threshold check only)
    /// the ones that do verify carry too little weight.
    ///
    /// Returned from exactly two places, which share this variant on purpose:
    ///
    /// - [`verify_entry`](crate::verify_entry): no signable node (the
    ///   top-level address, or for `Delegated` any delegate) carries a valid
    ///   ed25519 signature over the preimage. That covers a signature over a
    ///   different payload (e.g. another network passphrase), a key that is
    ///   not the node's own address, a missing or wrongly-shaped signature
    ///   `ScVal`, and a node whose address is not an ed25519 account. None of
    ///   those can verify, and the caller's only safe response is the same.
    /// - [`verify_delegated_threshold`](crate::verify_delegated_threshold):
    ///   the summed weight of delegates whose signatures verify is below
    ///   `threshold`. Here the individual signatures may all be genuine; what
    ///   fails is that they do not add up to an authorization the account
    ///   would accept. Signatures that do not verify, and signers absent from
    ///   `signers_with_weights`, contribute nothing rather than erroring.
    ///
    /// The threshold case is a deliberate fold-in rather than a separate
    /// variant: in both cases the entry is not validly signed for the policy
    /// being checked, and the two are already told apart by which function
    /// the caller invoked — `verify_entry` never checks a threshold.
    InvalidSignature,
    /// A signer's address matches no credential node (top-level address or
    /// delegate) in the entry being signed.
    ///
    /// Only returned for address-bearing credentials (`Address`,
    /// `AddressV2`, `AddressWithDelegates`). `SourceAccount` credentials
    /// have no node to match at all, so they are reported as
    /// [`SorochargeError::UnsupportedCredentialType`] instead.
    NoMatchingCredentialNode,
    /// A simulation's events could not be decoded, or a payment-shaped
    /// balance event from the asset contract (`transfer`, or the CAP-67
    /// issuer-side `mint` / `burn` it degenerates into) lacks the topics or
    /// data its shape must carry.
    ///
    /// Every return site is in
    /// [`verify_transfer_effects`](crate::verify_transfer_effects): an event
    /// that is not base64 `DiagnosticEvent` XDR; a `transfer` without
    /// `from`/`to` address topics; a `mint` without a `to` address topic; a
    /// `burn` without a `from` address topic; or any of those three whose data
    /// is not an `i128`. `reason` names which. Only events from the asset
    /// contract reach these shape checks — a balance event from any other
    /// contract is [`UnexpectedBalanceChange`](Self::UnexpectedBalanceChange)
    /// whatever its shape, and a `clawback` is rejected as unexpected without
    /// being shape-checked.
    SimulationEventsMalformed { reason: String },
    /// The simulation shows a balance change other than the expected payment.
    ///
    /// Every return site is in
    /// [`verify_transfer_effects`](crate::verify_transfer_effects): a balance
    /// event emitted by a contract other than the asset; a `clawback`; more
    /// than one balance event; or a single `transfer` / `mint` / `burn` whose
    /// payer, recipient or amount differs from the expected payment.
    ///
    /// One return site is a deliberate fold-in: when the caller's
    /// `asset_contract` is not a contract (`C...`) address at all, no event
    /// can come from it, so no simulation could ever show the expected
    /// payment. That is reported here, with `reason` "asset address is not a
    /// contract", before any event is read — failing closed — rather than
    /// through a separate variant for a caller-argument error only this one
    /// function can hit.
    UnexpectedBalanceChange { reason: String },
    /// The simulation does not show the expected payment transfer at all.
    ///
    /// Returned from one place,
    /// [`verify_transfer_effects`](crate::verify_transfer_effects), when the
    /// events contain no balance-moving event (`transfer`, `mint`, `burn` or
    /// `clawback`) whatsoever — including an empty event list. Non-contract
    /// events and contract events of other names are ignored. "At all" is
    /// literal: a balance event that is present but wrong (another payer,
    /// recipient or amount, or from another contract) is
    /// [`UnexpectedBalanceChange`](Self::UnexpectedBalanceChange), not this.
    ExpectedTransferMissing,
    /// The `Signer` implementation returned an error while signing a preimage.
    ///
    /// This crate never constructs this variant itself: it is the error a
    /// caller's `Signer::sign_preimage` reports, which `sign_entry`
    /// propagates unchanged.
    SigningFailed { reason: String },
    /// `Signer::address()` returned something other than an Ed25519 account
    /// (`G...`) — e.g. a contract (`C...`) or muxed address — so there is no
    /// public key to place in the `{public_key, signature}` credential
    /// signature. Carries the offending address as a strkey.
    UnsupportedSignerAddress { address: String },
    /// Constructing or serializing an XDR structure failed: a value did not
    /// fit its XDR-constrained shape (a `VecM`/`ScSymbol`/`ScBytes` length
    /// limit) or `to_xdr` serialization of an address or `HashIdPreimage`
    /// failed.
    ///
    /// Audited for issue #271: every call site in `entry.rs` and `sign.rs` is
    /// a genuine XDR construction or serialization failure. The one site that
    /// was not — an OS entropy failure while drawing the entry's nonce — now
    /// returns [`NonceGenerationFailed`](Self::NonceGenerationFailed) instead.
    XdrEncodingFailed { reason: String },
    /// The operating system's random-number source failed while drawing the
    /// entry's nonce in `build_charge_entry`.
    ///
    /// Distinct from [`XdrEncodingFailed`](Self::XdrEncodingFailed): nothing
    /// about the caller's input is malformed, and retrying may succeed once
    /// the entropy source recovers. The entry is never built with a fallback
    /// or predictable nonce — failing closed is the point of this variant.
    NonceGenerationFailed { reason: String },
    /// The entry's amount is non-positive (zero or negative), which is
    /// semantically invalid for a SEP-41 transfer.
    AmountNonPositive,
    /// The network passphrase does not match any known Stellar network
    /// (currently only the pubnet and testnet passphrases, which map to the
    /// CAIP-2 ids `stellar:pubnet` / `stellar:testnet`).
    ///
    /// `network` carries the rejected passphrase verbatim — not a CAIP-2 id.
    UnsupportedNetwork { network: String },
}

impl fmt::Display for SorochargeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress { strkey } => {
                write!(f, "invalid strkey address: {strkey}")
            }
            Self::UnsupportedCredentialType => {
                write!(f, "unsupported Soroban credential type")
            }
            Self::EmptyDelegateSigners => {
                write!(f, "delegated credential requires at least one signer")
            }
            Self::DuplicateDelegateSigner => {
                write!(f, "delegated credential lists the same signer address more than once")
            }
            Self::ExpiredEntry {
                valid_until_ledger,
                current_ledger,
            } => write!(
                f,
                "entry expired: valid until ledger {valid_until_ledger}, current ledger {current_ledger}"
            ),
            Self::ExpirationExceedsAllowance {
                signature_expiration_ledger,
                allowed_until_ledger,
            } => write!(
                f,
                "entry's expiration ledger {signature_expiration_ledger} exceeds the allowed {allowed_until_ledger}"
            ),
            Self::UnexpectedInvocationShape => write!(
                f,
                "entry does not authorize a single SEP-41 transfer(from, to, amount) call"
            ),
            Self::AssetMismatch => write!(f, "asset contract does not match expected charge"),
            Self::PayerMismatch => write!(f, "authorizing address does not match expected payer"),
            Self::AmountMismatch => write!(f, "amount does not match expected charge"),
            Self::AmountNonPositive => write!(f, "amount must be positive (non-zero)"),
            Self::RecipientMismatch => write!(f, "recipient does not match expected charge"),
            Self::InvalidSignature => write!(f, "signature is invalid for the entry's credential"),
            Self::SimulationEventsMalformed { reason } => {
                write!(f, "simulation events malformed: {reason}")
            }
            Self::UnexpectedBalanceChange { reason } => {
                write!(f, "unexpected balance change in simulation: {reason}")
            }
            Self::ExpectedTransferMissing => {
                write!(f, "simulation does not show the expected transfer")
            }
            Self::NoMatchingCredentialNode => write!(
                f,
                "signer's address matches no credential node in this entry"
            ),
            Self::UnsupportedNetwork { network } => write!(f, "unsupported network: {network}"),
            Self::SigningFailed { reason } => write!(f, "signing failed: {reason}"),
            Self::UnsupportedSignerAddress { address } => write!(
                f,
                "signer address must be an Ed25519 account (G...), got {address}"
            ),
            Self::XdrEncodingFailed { reason } => write!(f, "XDR encoding failed: {reason}"),
            Self::NonceGenerationFailed { reason } => {
                write!(f, "failed to generate nonce: {reason}")
            }
        }
    }
}

impl std::error::Error for SorochargeError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entropy failure must not be reported as an XDR problem: a caller
    /// triaging `XdrEncodingFailed` goes looking at its own inputs, which are
    /// fine here (issue #271).
    #[test]
    fn nonce_generation_failed_is_distinct_from_xdr_encoding_failed() {
        let nonce = SorochargeError::NonceGenerationFailed {
            reason: "entropy source unavailable".to_string(),
        };
        let xdr = SorochargeError::XdrEncodingFailed {
            reason: "entropy source unavailable".to_string(),
        };
        assert_ne!(nonce, xdr);
        assert_eq!(
            nonce.to_string(),
            "failed to generate nonce: entropy source unavailable"
        );
        assert!(!nonce.to_string().contains("XDR"));
    }
}
