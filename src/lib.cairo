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
    use core::starknet::syscalls;
    use starknet::storage::{
        StoragePathEntry,
        StoragePointerReadAccess,
        StoragePointerWriteAccess,
        StorageMapReadAccess,
        VecTrait,
        Map,
        Vec,
        MutableVecTrait
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
        SetContextValueSuccess,
    };

    use starknet::syscalls::replace_class_syscall;

    // First, add new types for mutation requests
    #[derive(Drop, Serde)]
    pub enum ProxyMutateRequest {
        Propose: ProposalWithArgs,
        Approve: ConfirmationRequestWithSigner,
    }

    #[starknet::storage_node]
    pub struct Approvals {
        approvals: Map<felt252, (ContextIdentity, bool)>,
        approval_keys: Vec<felt252>,
        approvals_count: u32,
    }

    #[starknet::storage_node]
    pub struct ContextStorage {
        pub values: Map::<felt252, Vec<felt252>>,  // hash -> value array
        pub keys: Map::<felt252, Vec<felt252>>,    // hash -> original key array
        pub indexes: Vec<felt252>,                 // list of hashes for iteration
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
        context_storage: ContextStorage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ExternalCallSuccess: ExternalCallSuccess,
        TransferSuccess: TransferSuccess,
        SetContextValueSuccess: SetContextValueSuccess,
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
        fn mutate(ref self: ContractState, request: Signed) -> ProposalWithApprovals {
            let mut serialized = request.payload.span();
            let mutate_request: ProxyMutateRequest = Serde::deserialize(ref serialized).unwrap();
            
            match mutate_request {
                ProxyMutateRequest::Propose(proposal) => {
                    // Verify signature matches the proposal author
                    assert(self.verify_signature(request, proposal.author_id.clone()), 'Invalid signature');
                    
                    let author_id = self.create_identity_key(@proposal.author_id);
                    let num_proposals = self.proxy_contract.num_proposals_pk.read(author_id);
                    assert!(
                        num_proposals <= self.proxy_contract.active_proposals_limit.read(),
                        "Account has too many active proposals"
                    );
                    
                    self.perform_action_by_member(MemberAction::Create((proposal, num_proposals)))
                },
                ProxyMutateRequest::Approve(confirmation_request) => {
                    // Verify signature matches the signer
                    assert(
                        self.verify_signature(request, confirmation_request.signer_id.clone()),
                        'Invalid signature'
                    );
                    
                    self.perform_action_by_member(
                        MemberAction::Approve((confirmation_request.signer_id, confirmation_request.proposal_id))
                    )
                }
            }
        }

        fn get_confirmations_count(self: @ContractState, proposal_id: ProposalId) -> ProposalWithApprovals {
            let current_proposal = self.proxy_contract.approvals.entry(proposal_id);
            let size = current_proposal.approvals_count.read();
    
            ProposalWithApprovals {
                proposal_id,
                num_approvals: size,
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

        fn get_context_value(
            self: @ContractState, 
            key: Array<felt252>
        ) -> Option<Array<felt252>> {
            // Create storage key from the input key array
            let storage_key = poseidon_hash_span(key.span());
            
            // Get the value array from storage
            let value_vec = self.proxy_contract.context_storage.values.entry(storage_key);
            
            // Check if value exists (length > 0)
            if value_vec.len() == 0 {
                return Option::None;
            }
            
            // Convert storage Vec to regular Array
            let mut value_array = ArrayTrait::new();
            let mut i: u64 = 0;
            loop {
                if i >= value_vec.len().into() {
                    break;
                }
                value_array.append(value_vec.at(i.try_into().unwrap()).read());
                i += 1;
            };
            
            Option::Some(value_array)
        }

        fn context_storage_entries(
            self: @ContractState,
            offset: u32,
            length: u32
        ) -> Array<(Array<felt252>, Array<felt252>)> {
            let mut entries = ArrayTrait::new();
    
            // Convert len to u32 right away
            let indexes_len: u32 = self.proxy_contract.context_storage.indexes.len().try_into().unwrap();
            
            // Now all types are u32
            let start = offset;
            let end = if offset + length > indexes_len {
                indexes_len
            } else {
                offset + length
            };
            
            // Iterate through the range
            let mut i = start;
            loop {
                if i >= end {
                    break;
                }
                
                // Get storage key from indexes
                let storage_key = self.proxy_contract.context_storage.indexes.at(i.try_into().unwrap()).read();
                
                // Get key and value arrays for this storage key
                let key_vec = self.proxy_contract.context_storage.keys.entry(storage_key);
                let value_vec = self.proxy_contract.context_storage.values.entry(storage_key);
                
                // Create arrays to hold the data
                let mut key_array = ArrayTrait::new();
                let mut value_array = ArrayTrait::new();
                
                // Read key data
                let mut j: u64 = 0;
                loop {
                    if j >= key_vec.len().into() {
                        break;
                    }
                    key_array.append(key_vec.at(j.try_into().unwrap()).read());
                    j += 1;
                };
                
                // Read value data
                let mut j: u64 = 0;
                loop {
                    if j >= value_vec.len().into() {
                        break;
                    }
                    value_array.append(value_vec.at(j.try_into().unwrap()).read());
                    j += 1;
                };
                
                // Add the pair to entries
                entries.append((key_array, value_array));
                i += 1;
            };
            
            entries
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
                ProposalActionWithArgs::Transfer((recipient, amount, token_address)) => 
                    (ProposalAction::Transfer((recipient, amount, token_address)), ArrayTrait::new()),
                ProposalActionWithArgs::SetNumApprovals(v) => 
                    (ProposalAction::SetNumApprovals(v), ArrayTrait::new()),
                ProposalActionWithArgs::SetActiveProposalsLimit(v) => 
                    (ProposalAction::SetActiveProposalsLimit(v), ArrayTrait::new()),
                ProposalActionWithArgs::SetContextValue((key, value)) => {
                    let storage_key = poseidon_hash_span(key.span());
                    
                    // Create args array with lengths and data
                    let mut full_args = ArrayTrait::new();
                    // Add lengths first
                    full_args.append(key.len().into());
                    full_args.append(value.len().into());
                    
                    // Add key data
                    let mut i = 0;
                    loop {
                        if i >= key.len() {
                            break;
                        }
                        full_args.append(*key.at(i));
                        i += 1;
                    };
                    
                    // Add value data
                    let mut i = 0;
                    loop {
                        if i >= value.len() {
                            break;
                        }
                        full_args.append(*value.at(i));
                        i += 1;
                    };
                    
                    (ProposalAction::SetContextValue(storage_key), full_args)
                }
            };
            new_proposal.actions.write(storage_action);

            // Store args if any exist (this part handles both external calls and context storage)
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
                ProposalAction::SetContextValue(storage_key) => {
                    // Get the arguments from storage
                    let args = self.proposal_action_arguments.entry(proposal_id);

                    // Read lengths and convert to u64
                    let key_len: u64 = args.at(0).read().try_into().unwrap();
                    let value_len: u64 = args.at(1).read().try_into().unwrap();
                    
                    // Create arrays for key and value
                    let mut keys = ArrayTrait::<felt252>::new();
                    let mut values = ArrayTrait::<felt252>::new();
                    
                    let mut i: u64 = 2;
                    loop {
                        if i >= key_len + 2 {
                            break;
                        }
                        keys.append(args.at(i).read());
                        i += 1;
                    };

                    loop {
                        if i >= key_len + value_len + 2 {
                            break;
                        }
                        values.append(args.at(i).read());
                        i += 1;
                    };

                    // Check if key exists
                    let existing_key = self.proxy_contract.context_storage.keys.entry(storage_key);
                    
                    if existing_key.len() == 0 {
                        // New key - store and track it
                        let mut key_vec = self.proxy_contract.context_storage.keys.entry(storage_key);
                        let mut value_vec = self.proxy_contract.context_storage.values.entry(storage_key);


                        let mut i: u64 = 0;
                        loop {
                            if i >= key_len {
                                break;
                            }
                            key_vec.append().write(*keys.at(i.try_into().unwrap()));
                            i += 1;
                        };
                        i = 0;
                        loop {
                            if i >= value_len {
                                break;
                            }
                            value_vec.append().write(*values.at(i.try_into().unwrap()));
                            i += 1;
                        };
                        
                        self.proxy_contract.context_storage.indexes.append().write(storage_key);
                    } else {
                        // Update existing value only
                        let mut value_vec = self.proxy_contract.context_storage.values.entry(storage_key);
                        let mut i: u64 = 0;
                        loop {
                            if i >= value_len {
                                break;
                            }
                            let mut storage_ptr = value_vec.at(i.try_into().unwrap());
                            storage_ptr.write(*values.at(i.try_into().unwrap()));
                            i += 1;
                        };
                    }
                    self.emit(Event::SetContextValueSuccess(SetContextValueSuccess {
                        message: "Set context value successful"
                    }));
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
