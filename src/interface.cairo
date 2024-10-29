use super::types::{Signed, ProposalId, SignerId, ProposalWithApprovals};

#[starknet::interface]
pub trait IProxyContract<TContractState> {
    fn create_and_approve_proposal(ref self: TContractState, signed_proposal: Signed) -> ProposalWithApprovals;
    fn approve(ref self: TContractState, request: Signed) -> ProposalWithApprovals;
    fn internal_confirm(ref self: TContractState, proposal_id: ProposalId, signer_id: SignerId);
    // fn call_proxy_contract(self: @TContractState, contract_address: ContractAddress, context_id: ContextId) -> Option<Application>;
}