// use core::starknet::storage::{Map};
// use starknet::Map;

use starknet::ContractAddress;
#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub type ProposalId = u32;
#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub type SignerId = felt252;
#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub type ContextId = felt252;
#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub type ContextIdentity = felt252;

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub struct ProposalWithApprovals {
    pub proposal_id: ProposalId,
    pub num_approvals: usize,
}

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub enum MemberAction {
    Approve: (SignerId, ProposalId),
    Create: (Proposal, u32),
}

#[derive(Clone, Debug)]
pub struct FunctionCallPermission {
    allowance: Option<u128>,
    receiver_id: ContextIdentity,
    method_names: Array<ByteArray>,
}
// An internal request wrapped with the signer_pk and added timestamp to determine num_requests_pk and prevent against malicious key holder gas attacks

// An internal request wrapped with the signer_pk and added timestamp to determine num_requests_pk and prevent against malicious key holder gas attacks
#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub struct ConfirmationRequestWithSigner {
    pub proposal_id: ProposalId,
    pub signer_id: SignerId,
    pub added_timestamp: u64,
}

#[derive(Drop, Clone, Serde)]
pub struct Approvals {
    pub approvals: Array<SignerId>,
}

/// Lowest level action that can be performed by the multisig contract.
#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub enum ProposalAction {
    // FunctionCall: (function_selector, function_call_args),
    FunctionCall:(felt252, felt252),
}

// The request the user makes specifying the receiving account and actions they want to execute (1 tx)
#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub struct Proposal {
    pub receiver_id: ContractAddress,
    pub author_id: ContextIdentity,
    pub actions: ProposalAction,
}

#[derive(Drop, Serde, Debug)]
pub struct Signed {
    pub payload: Array<felt252>,
    pub signature_r: felt252,
    pub signature_s: felt252,
}