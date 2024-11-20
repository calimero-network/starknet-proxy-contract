pub mod types;
pub use types::{
    ContextId, 
    ContextIdentity, 
    ProposalId, 
    // SignerId, 
    Signed, 
    ProposalWithApprovals,
    ExternalCallSuccess,
    TransferSuccess,
};
// use starknet::ContractAddress;

#[starknet::interface]
pub trait IContextConfig<TContractState> {
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
pub mod ProxyContract {
    use starknet::ContractAddress;
    use starknet::ClassHash;
    use starknet::storage::{
        Map,
        Vec,
        MutableVecTrait
    };
    use core::starknet::syscalls;
    use starknet::storage::{
        StoragePathEntry,
        StoragePointerReadAccess,
        StoragePointerWriteAccess,
        StorageMapReadAccess,
    };

    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use core::poseidon::poseidon_hash_span;
    use core::ecdsa::check_ecdsa_signature;
    use openzeppelin_access::ownable::OwnableComponent;
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    use super::{IContextConfigDispatcher, IContextConfigDispatcherTrait};

    use proxy_contract::types::{
        ContextId,
        ProposalId,
        ProposalWithArgs,
        ProposalActionWithArgs,
        Proposal,
        ProposalAction,
        Signed,
        ContextIdentity,
        MemberAction,
        ConfirmationRequestWithSigner,
        ProposalWithApprovals,
        ExternalCallSuccess,
        TransferSuccess,
    };

    use starknet::syscalls::replace_class_syscall;

    #[starknet::storage_node]
    pub struct Approvals {
        approvals: Map<felt252, (ContextIdentity, bool)>,
        approval_keys: Vec<felt252>,
        approvals_count: u32,
    }

    #[starknet::storage_node]
    struct ProxyContract {
        context_id: ContextId,
        context_config_account_id: ContractAddress,
        num_approvals: u32,
        proposal_nonce: ProposalId,
        num_proposals_pk: Map::<felt252, u32>,
        active_proposals_limit: u32,
        approvals: Map::<ProposalId, Approvals>,
        proposals: Map::<ProposalId, Proposal>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ExternalCallSuccess: ExternalCallSuccess,
        TransferSuccess: TransferSuccess,
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

            assert(self.verify_signature(signed_proposal, proposal.author_id.clone()), 'Invalid signature');
    
            let author_id = self.create_identity_key(@proposal.author_id);
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

            assert(self.verify_signature(request, confirmation_request.signer_id.clone()), 'Invalid signature');

            return self.perform_action_by_member(MemberAction::Approve((confirmation_request.signer_id, confirmation_request.proposal_id)));
        }

        fn internal_confirm(ref self: ContractState, proposal_id: ProposalId, signer_id: ContextIdentity) {
            let mut current_proposal_approvals = self.proxy_contract.approvals.entry(proposal_id);
            let signer_id_key = self.create_identity_key(@signer_id);
            
            // Read the full tuple (identity, approval status)
            let approval_entry = current_proposal_approvals.approvals.entry(signer_id_key).read();
            if approval_entry == (signer_id.clone(), true) {
                assert!(false, "Already confirmed this request with this key");
            }
            
            // Store both the identity and the approval status
            current_proposal_approvals.approvals.entry(signer_id_key).write((signer_id, true));
            // Add the key to our list
            current_proposal_approvals.approval_keys.append().write(signer_id_key);
            
            let new_approvals_count = current_proposal_approvals.approvals_count.read() + 1;
            current_proposal_approvals.approvals_count.write(new_approvals_count);

            if new_approvals_count >= self.proxy_contract.num_approvals.read() {
                let request = self.remove_request(proposal_id);
                self.execute_proposal(request, proposal_id);
            }
        }

        // Add a helper function to get all approvers for a proposal
        fn get_proposal_approvers(ref self: ContractState, proposal_id: ProposalId) -> Array<ContextIdentity> {
            let mut approvers = ArrayTrait::new();
            let current_proposal = self.proxy_contract.approvals.entry(proposal_id);
            let keys = current_proposal.approval_keys;
            
            // Iterate through all stored approval keys
            let keys_len = keys.len();
            let mut i = 0;
            loop {
                if i >= keys_len {
                    break;
                }
                
                let key = keys.at(i).read();
                // Get the identity from the approvals map
                let (identity, approved) = current_proposal.approvals.entry(key).read();
                if approved {
                    approvers.append(identity);
                }
                
                i += 1;
            };
            
            approvers
        }

        fn upgrade_contract(ref self: ContractState, class_hash: ClassHash) {
            // Check if caller is the context config contract
            let caller = starknet::get_caller_address();
            assert(
                caller == self.proxy_contract.context_config_account_id.read(),
                'only context contract'
            );
            
            // Perform the upgrade
            replace_class_syscall(class_hash).unwrap();
        }
    }


    #[generate_trait]
    impl SignatureVerifier of SignatureVerifierTrait {
        fn verify_signature(self: @ContractState, signed_request: Signed, signer_id: ContextIdentity) -> bool {
            let mut serialized = signed_request.payload.span();
            let message_hash = poseidon_hash_span(serialized);

            // Reconstruct the 32-byte public key from high and low parts
            // Each part is 16 bytes, so we need to shift high by 16 bytes (128 bits)
            let full_public_key = signer_id.high * 0x100000000000000000000000000000000 + signer_id.low;

            check_ecdsa_signature(
                message_hash, 
                full_public_key, 
                signed_request.signature_r, 
                signed_request.signature_s
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
            let proposal_author = proposal.author_id.clone();
            
            // Check if the author is zero
            if proposal_author.high == 0 && proposal_author.low == 0 {
                assert!(false, "Invalid proposal author");
            }

            // Create storage key from author identity
            let author_key = self.create_identity_key(@proposal_author);
            let mut num_requests = self.proxy_contract.num_proposals_pk.entry(author_key).read();
            if num_requests > 0 {
                num_requests = num_requests - 1;
            }
            
            let mut new_proposal = self.proxy_contract.proposals.entry(proposal_id);
            new_proposal.proposal_id.write(0);
            // Write zero ContextIdentity
            new_proposal.author_id.write(ContextIdentity { high: 0, low: 0 });
            self.proxy_contract.num_proposals_pk.entry(author_key).write(num_requests);
            proposal
        }

        fn internal_create_proposal(ref self: ContractState, proposal_with_args: ProposalWithArgs, num_proposals: u32,) -> ProposalWithApprovals {
            // assert_membership(call_result);

            // Create storage key from author_id
            let author_key = self.create_identity_key(@proposal_with_args.author_id);
            self.proxy_contract.num_proposals_pk.entry(author_key).write(num_proposals);
            
            let proposal_id = self.proxy_contract.proposal_nonce.read();
            let mut new_proposal = self.proxy_contract.proposals.entry(proposal_id);
            new_proposal.proposal_id.write(proposal_id);
            new_proposal.author_id.write(proposal_with_args.author_id.clone());

            let (storage_action, args) = match proposal_with_args.actions {
                ProposalActionWithArgs::ExternalFunctionCall((addr, selector, args)) => {
                    (ProposalAction::ExternalFunctionCall((addr, selector)), args)
                },
                ProposalActionWithArgs::Transfer((recipient, amount, token_address)) => (ProposalAction::Transfer((recipient, amount, token_address)), ArrayTrait::new()),
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
                ProposalAction::ExternalFunctionCall((contract_address, selector)) => {
                    // Get the arguments for this call from storage
                    let mut calldata = ArrayTrait::new();
                    let call_args = self.proposal_action_arguments.entry(proposal_id);
                    let call_args_len = call_args.len();
                    for i in 0..call_args_len {
                        calldata.append(call_args.at(i).read());
                    };
                    
                     // Execute the cross-contract call
                    let syscall_result = syscalls::call_contract_syscall(
                        contract_address,  // target contract address
                        selector,         // function selector - method name
                        calldata.span()   // arguments as span
                    );

                    // Execute the cross-contract call
                    match syscall_result {
                        Result::Ok(retdata) => {
                            // Call successful, can handle response if needed
                            self.emit(ExternalCallSuccess {
                                message: format!("External call successful with return data: {:?}", retdata)
                            });
                        },
                        Result::Err(revert_reason) => {
                            // Just pass through the original error array
                            panic(revert_reason);
                        }
                    }
                },
                ProposalAction::Transfer((recipient, amount, token_address)) => {
                    // Create ERC20 dispatcher
                    let erc20_dispatcher = IERC20Dispatcher { contract_address: token_address };
                    
                    // Execute the transfer
                    let success = erc20_dispatcher.transfer(recipient, amount);
                    assert(success, 'Transfer failed');
                    
                    self.emit(Event::TransferSuccess(TransferSuccess {
                        message: "Transfer successful"
                    }));
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
    
    #[generate_trait]
    impl StorageHelpers of StorageHelpersTrait {
        // Helper to create storage key from context_id
        fn create_context_key(self: @ContractState, context_id: @ContextId) -> felt252 {
            poseidon_hash_span(array![*context_id.high, *context_id.low].span())
        }

        // Helper to create storage key from context_id and identity
        fn create_member_key(
            self: @ContractState, 
            context_id: @ContextId, 
            identity: @ContextIdentity
        ) -> felt252 {
            let context_key = self.create_context_key(context_id);
            let identity_key = self.create_identity_key(identity);
            poseidon_hash_span(array![context_key, identity_key].span())
        }

        // Helper to create storage key from identity
        fn create_identity_key(self: @ContractState, identity: @ContextIdentity) -> felt252 {
            poseidon_hash_span(array![*identity.high, *identity.low].span())
        }
    }
}
