pub mod types;
pub use types::{ContextId, ContextIdentity, ProposalId, SignerId, Signed, ProposalWithApprovals};
// use starknet::ContractAddress;

#[starknet::interface]
pub trait IContextConfig<TContractState> {
    // fn has_member(self: @TContractState, context_id: ContextId, identity: ContextIdentity) -> bool;
    fn has_member(self: @TContractState, context_id: ContextId, identity: ContextIdentity) -> bool;
}

pub mod interface;
pub use interface::{
    IProxyContract, 
    IProxyContractDispatcher, 
    IProxyContractDispatcherTrait, 
    IProxyContractSafeDispatcher, 
    IProxyContractSafeDispatcherTrait
};


#[starknet::contract]
mod ProxyContract {
    // use starknet::event::EventEmitter;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map,
        Vec,
        VecTrait,
        MutableVecTrait
    };
    use core::starknet::{syscalls, SyscallResultTrait};
    use starknet::storage::{
        StoragePathEntry,
        StoragePointerReadAccess,
        StoragePointerWriteAccess,
        StorageMapReadAccess,
        // StorageMapWriteAccess,
        // VecTrait
    };

    use core::poseidon::poseidon_hash_span;
    use core::ecdsa::check_ecdsa_signature;
    use openzeppelin_access::ownable::OwnableComponent;
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    use super::{IContextConfigDispatcher, IContextConfigDispatcherTrait};

    use proxy_contract::types::{
        ContextId,
        ProposalId,
        SignerId,
        ProposalWithArgs,
        ProposalActionWithArgs,
        // ProposalStorage,
        Proposal,
        ProposalAction,
        // ProposalActionStorage,
        // ProposalActionRequest,
        Signed,
        ContextIdentity,
        MemberAction,
        ConfirmationRequestWithSigner,
        ProposalWithApprovals,
    };

    #[starknet::storage_node]
    pub struct Approvals {
        approvals: Map<SignerId, bool>,
        approvals_count: u32,
    }

    #[starknet::storage_node]
    struct ProxyContract {
        context_id: ContextId,
        context_config_account_id: ContractAddress,
        num_approvals: u32,
        proposal_nonce: ProposalId,
        num_proposals_pk: Map::<SignerId, u32>,
        active_proposals_limit: u32,
        approvals: Map::<ProposalId, Approvals>,
        proposals: Map::<ProposalId, Proposal>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event
    }

    #[storage]
    struct Storage {
        proxy_contract: ProxyContract,
        proposal_action_arguments: Map::<ProposalId, Vec<felt252>>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, context_id: ContextId, context_config_account_id: ContractAddress) {
        self.ownable.initializer(owner);
        self.proxy_contract.context_id.write(context_id);
        self.proxy_contract.context_config_account_id.write(context_config_account_id);
        self.proxy_contract.proposal_nonce.write(0);
        self.proxy_contract.num_approvals.write(3);
        self.proxy_contract.active_proposals_limit.write(10);
    }

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl InternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl ProxyContractImpl of super::interface::IProxyContract<ContractState> {
        fn create_and_approve_proposal(ref self: ContractState, signed_proposal: Signed) -> ProposalWithApprovals {
            // Verify the signature corresponds to the signer_id
            let mut serialized = signed_proposal.payload.span();
            let proposal: ProposalWithArgs = Serde::deserialize(ref serialized).unwrap();

            assert(self.verify_signature(signed_proposal, proposal.author_id), 'Invalid signature');
    
            let author_id = proposal.author_id;
    
            let num_proposals = self.proxy_contract.num_proposals_pk.read(author_id);
            assert!(
                num_proposals <= self.proxy_contract.active_proposals_limit.read(),
                "Account has too many active proposals. Confirm or delete some."
            );
            return self.perform_action_by_member(MemberAction::Create((proposal, num_proposals)));
        }

        fn approve(ref self: ContractState, request: Signed) -> ProposalWithApprovals {
            let mut serialized = request.payload.span();
            let confirmation_request: ConfirmationRequestWithSigner = Serde::deserialize(ref serialized).unwrap();

            assert(self.verify_signature(request, confirmation_request.signer_id), 'Invalid signature');

            return self.perform_action_by_member(MemberAction::Approve((confirmation_request.signer_id, confirmation_request.proposal_id)));
        }

        fn internal_confirm(ref self: ContractState, proposal_id: ProposalId, signer_id: SignerId) {
            // let approvals = self.proxy_contract.approvals.entry(request_id);
            let mut current_proposal_approvals = self.proxy_contract.approvals.entry(proposal_id);
            let approval_exists = current_proposal_approvals.approvals.entry(signer_id).read();
            if approval_exists {
                assert!(false, "Already confirmed this request with this key");
            }
            let approvals_count = current_proposal_approvals.approvals_count.read();
            if approvals_count >= self.proxy_contract.num_approvals.read() {
                let request = self.remove_request(proposal_id);
                self.execute_proposal(request, proposal_id);
            } else {
                current_proposal_approvals.approvals.entry(signer_id).write(true);
                current_proposal_approvals.approvals_count.write(approvals_count + 1);
            }
        }
    }


    #[generate_trait]
    impl SignatureVerifier of SignatureVerifierTrait {
        fn verify_signature(self: @ContractState, signed_request: Signed, signer_id: ContextIdentity) -> bool {
            // Hash the payload using Poseidon hash
            let hash = poseidon_hash_span(signed_request.payload.span());
            check_ecdsa_signature(
                hash,  // message hash
                signer_id,  // public key
                signed_request.signature_r,  // r
                signed_request.signature_s   // s
            )
        }
    }

    #[generate_trait]
    impl ProxyActions of ProxyActionsTrait {
        fn perform_action_by_member(ref self: ContractState, action: MemberAction) -> ProposalWithApprovals {
            let identity = match action.clone() {
                MemberAction::Approve((identity, _)) => identity,
                MemberAction::Create((proposal, _)) => proposal.author_id,
            };
            let context_config_dispatcher = IContextConfigDispatcher { contract_address: self.proxy_contract.context_config_account_id.read() };
            let is_member = context_config_dispatcher.has_member(self.proxy_contract.context_id.read(), identity);
            assert!(is_member, "Not a context member");
            match action {
                MemberAction::Approve((identity, request_id)) => {
                    self.internal_confirm(request_id, identity);
                    self.get_confirmations_count(request_id)
                },
                MemberAction::Create((proposal, num_proposals)) => 
                    self.internal_create_proposal(proposal, num_proposals),
            }
        }

        fn remove_request(ref self: ContractState, proposal_id: ProposalId) -> Proposal {
            let proposal = self.proxy_contract.proposals.entry(proposal_id).read();
            let proposal_author = proposal.author_id;
            if proposal_author == 0 {
                assert!(false, "Invalid proposal author");
            }
            let mut num_requests = self.proxy_contract.num_proposals_pk.entry(proposal_author).read();
            if num_requests > 0 {
                num_requests = num_requests - 1;
            }
            
            let mut new_proposal = self.proxy_contract.proposals.entry(proposal_id);
            new_proposal.receiver_id.write(core::num::traits::Zero::<ContractAddress>::zero());
            new_proposal.author_id.write(0);
            self.proxy_contract.num_proposals_pk.entry(proposal_author).write(num_requests);
            proposal
        }

        fn internal_create_proposal(ref self: ContractState, proposal_with_args: ProposalWithArgs, num_proposals: u32,) -> ProposalWithApprovals {
            // assert_membership(call_result);

            self.proxy_contract.num_proposals_pk.entry(proposal_with_args.author_id).write(num_proposals);
            let proposal_id = self.proxy_contract.proposal_nonce.read();
            let mut new_proposal = self.proxy_contract.proposals.entry(proposal_id);
            new_proposal.receiver_id.write(proposal_with_args.receiver_id);
            new_proposal.author_id.write(proposal_with_args.author_id);

            // Extract the arguments based on the action type
            let (storage_action, args) = match proposal_with_args.actions {
                ProposalActionWithArgs::ExternalFunctionCall((addr, selector, args, v1, v2)) => {
                    (ProposalAction::ExternalFunctionCall((addr, selector, v1, v2)), args)
                },
                ProposalActionWithArgs::Transfer(t) => (ProposalAction::Transfer(t), ArrayTrait::new()),
                ProposalActionWithArgs::SetNumApprovals(v) => (ProposalAction::SetNumApprovals(v), ArrayTrait::new()),
                ProposalActionWithArgs::SetActiveProposalsLimit(v) => (ProposalAction::SetActiveProposalsLimit(v), ArrayTrait::new()),
            };

            new_proposal.actions.write(storage_action);

            if !args.is_empty() { 
                let mut args_vec = self.proposal_action_arguments.entry(proposal_id);
                let mut i: usize = 0;
                loop {
                    if i >= args.len() {
                        break;
                    }
                    args_vec.append().write(*args.at(i));
                    i += 1;
                }
            }
            
            self.internal_confirm(proposal_id, proposal_with_args.author_id);

            self.proxy_contract.proposal_nonce.write(proposal_id + 1);

            return ProposalWithApprovals {
                proposal_id,
                num_approvals: self.get_confirmations_count(proposal_id).num_approvals,
            };
        }

        fn get_confirmations_count(ref self: ContractState, proposal_id: ProposalId) -> ProposalWithApprovals {
            let current_proposal = self.proxy_contract.approvals.entry(proposal_id);
            let size = current_proposal.approvals_count.read();
    
            ProposalWithApprovals {
                proposal_id,
                num_approvals: size,
            }
        }

        fn execute_proposal(ref self: ContractState, proposal: Proposal, proposal_id: ProposalId) {
            match proposal.actions {
                ProposalAction::ExternalFunctionCall((contract_address, method_name, deposit, gas)) => {
                    let mut args = array![];
                    let call_args = self.proposal_action_arguments.entry(proposal_id);
                    let call_args_len = call_args.len();
                    for i in 0..call_args_len {
                        args.append(call_args.at(i).read());
                    };
                    
                    let mut _res = syscalls::call_contract_syscall(
                        contract_address, method_name, args.span()
                    )
                    .unwrap_syscall();
        
                    // Serde::<bool>::deserialize(ref res).unwrap()
                },
                ProposalAction::Transfer((contract_address, amount)) => {
                    // syscalls::transfer_syscall(contract_address, amount).unwrap_syscall();
                },
                ProposalAction::SetNumApprovals(v) => {
                    self.proxy_contract.num_approvals.write(v);
                },
                ProposalAction::SetActiveProposalsLimit(v) => {
                    self.proxy_contract.active_proposals_limit.write(v);
                },
            }
        }
    
    }
    
}
