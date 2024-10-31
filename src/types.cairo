// use core::starknet::storage::{Map};
// use starknet::Map;
// use starknet::storage::{
//     StoragePointerReadAccess, StoragePointerWriteAccess, Vec, VecTrait, MutableVecTrait
// };

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
    Create: (ProposalWithArgs, u32),
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

#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub enum ProposalAction {
    ExternalFunctionCall:(ContractAddress, felt252, u128, u128),
    Transfer: (ContractAddress, u128),
    SetNumApprovals: u32,
    SetActiveProposalsLimit: u32,
}

#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub struct Proposal {
    pub receiver_id: ContractAddress,
    pub author_id: ContextIdentity,
    pub actions: ProposalAction,
}

// Runtime version used for contract calls
#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub enum ProposalActionWithArgs {
    ExternalFunctionCall: (ContractAddress, felt252, Array<felt252>, u128, u128),
    Transfer: (ContractAddress, u128),
    SetNumApprovals: u32,
    SetActiveProposalsLimit: u32,
}

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub struct ProposalWithArgs {
    pub receiver_id: ContractAddress,
    pub author_id: ContextIdentity,
    pub actions: ProposalActionWithArgs,
}

#[derive(Drop, Serde, Debug)]
pub struct Signed {
    pub payload: Array<felt252>,
    pub signature_r: felt252,
    pub signature_s: felt252,
}