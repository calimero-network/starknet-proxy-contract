use super::types::{
    Signed,
    ProposalId,
    ContextIdentity,
    ProposalWithApprovals
};

use starknet::ClassHash;

#[starknet::interface]
pub trait IProxyContract<TContractState> {
    fn create_and_approve_proposal(ref self: TContractState, signed_proposal: Signed) -> ProposalWithApprovals;
    fn approve(ref self: TContractState, request: Signed) -> ProposalWithApprovals;
    fn internal_confirm(ref self: TContractState, proposal_id: ProposalId, signer_id: ContextIdentity);
    fn get_proposal_approvers(ref self: TContractState, proposal_id: ProposalId) -> Array<ContextIdentity>;
    fn upgrade_contract(ref self: TContractState, class_hash: ClassHash);
    fn get_context_value(self: @TContractState, key: Array<felt252>) -> Option<Array<felt252>>;
    fn context_storage_entries(self: @TContractState, offset: u32, length: u32) -> Array<(Array<felt252>, Array<felt252>)>;
    
    // fn call_proxy_contract(self: @TContractState, contract_address: ContractAddress, context_id: ContextId) -> Option<Application>;
}