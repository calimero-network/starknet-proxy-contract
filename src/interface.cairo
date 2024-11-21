use super::types::{
    Signed,
    ProposalId,
    Proposal,
    ContextIdentity,
    ProposalWithApprovals
};

use starknet::ClassHash;

#[starknet::interface]
pub trait IProxyContract<TContractState> {
    fn mutate(ref self: TContractState, request: Signed) -> ProposalWithApprovals;
    fn get_confirmations_count(self: @TContractState, proposal_id: ProposalId) -> ProposalWithApprovals;
    fn get_proposal_approvers(ref self: TContractState, proposal_id: ProposalId) -> Array<ContextIdentity>;
    fn upgrade_contract(ref self: TContractState, class_hash: ClassHash);
    fn get_context_value(self: @TContractState, key: Array<felt252>) -> Option<Array<felt252>>;
    fn context_storage_entries(self: @TContractState, offset: u32, length: u32) -> Array<(Array<felt252>, Array<felt252>)>;
    fn proposals(self: @TContractState, offset: u32, length: u32) -> Array<Proposal>;
    fn proposal(self: @TContractState, proposal_id: ProposalId) -> Option<Proposal>;    
    fn get_num_approvals(self: @TContractState) -> u32;
    fn get_active_proposals_limit(self: @TContractState) -> u32;
}