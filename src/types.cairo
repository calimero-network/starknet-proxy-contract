use starknet::ContractAddress;
#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub struct ProposalId {
    pub high: felt252,
    pub low: felt252, 
}

#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub struct ContextId {
    pub high: felt252,
    pub low: felt252, 
}
#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub struct ContextIdentity {
    pub high: felt252,
    pub low: felt252, 
}

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub struct ProposalWithApprovals {
    pub proposal_id: ProposalId,
    pub num_approvals: usize,
}

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub enum MemberAction {
    Approve: (ContextIdentity, ProposalId),
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
    pub signer_id: ContextIdentity,
    pub added_timestamp: u64,
}

#[derive(Drop, Clone, Serde)]
pub struct Approvals {
    pub approvals: Array<ContextIdentity>,
}
// Storage version
#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub enum ProposalAction {
    ExternalFunctionCall:(ContractAddress, felt252),
    Transfer: (ContractAddress, u256, ContractAddress),
    SetNumApprovals: u32,
    SetActiveProposalsLimit: u32,
    SetContextValue: felt252,
}

#[derive(Drop, Serde)]
pub struct ProxyMutateRequestWrapper {
    pub signer_id: ContextIdentity,  // ECDSA verifying key
    pub kind: ProxyMutateRequest,    // The original request
}

#[derive(Drop, Serde)]
pub enum ProxyMutateRequest {
    Propose: ProposalWithArgs,
    Approve: ConfirmationRequestWithSigner,
}

#[derive(Drop, Clone, Serde, PartialEq, Debug, starknet::Store)]
pub struct Proposal {
    pub proposal_id: ProposalId,
    pub author_id: ContextIdentity,
    pub actions: ProposalAction,
}

// Runtime version used for contract calls
#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub enum ProposalActionWithArgs {
    ExternalFunctionCall:(ContractAddress, felt252, Array<felt252>),
    Transfer: (ContractAddress, u256, ContractAddress),
    SetNumApprovals: u32,
    SetActiveProposalsLimit: u32,
    SetContextValue: (Array<felt252>, Array<felt252>),
}

#[derive(Drop, Clone, Serde, PartialEq, Debug)]
pub struct ProposalWithArgs {
    pub proposal_id: ProposalId,
    pub author_id: ContextIdentity,
    pub actions: ProposalActionWithArgs,
}

#[derive(Drop, Serde, Debug)]
pub struct Signed {
    pub payload: Array<felt252>,
    pub signature_r: felt252,
    pub signature_s: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct ExternalCallSuccess {
    pub message: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct TransferSuccess {
    pub message: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct SetContextValueSuccess {
    pub message: ByteArray,
}

#[derive(Drop, starknet::Event)]
pub struct ProposalCreated {
    pub proposal_id: ProposalId,
    pub num_approvals: u32,
}