#[cfg(test)]
mod tests {

    use starknet::{
        ContractAddress, 
        ClassHash,
    };

    use snforge_std::{
        declare,
        get_class_hash,
        ContractClassTrait,
        DeclareResultTrait, 
        start_cheat_caller_address,
        stop_cheat_caller_address,
        EventSpyAssertionsTrait,
        spy_events,
        EventSpyTrait,
        EventSpy
    };

    use proxy_contract::{
        IProxyContractSafeDispatcher,
        IProxyContractSafeDispatcherTrait,
        IProxyContractDispatcher,
        IProxyContractDispatcherTrait,
    };

    use proxy_contract::ProxyContract::Event;

    use openzeppelin::token::erc20::interface::{
        IERC20Dispatcher, 
        IERC20DispatcherTrait,
    };

    use proxy_contract::types as proxy_types;
    use context_config::types as context_types;

    use context_config::i_context_configs::{
        IContextConfigsSafeDispatcher,
        IContextConfigsSafeDispatcherTrait,
    };

    use mock_external::{
        IMockExternalDispatcher,
        IMockExternalDispatcherTrait,
        IMockExternalSafeDispatcherTrait,
    };

    use core::traits::Into;
    use core::array::ArrayTrait;
    use core::byte_array::ByteArray;
    use core::byte_array::ByteArrayTrait;
    use core::option::OptionTrait;
    use core::result::ResultTrait;
    use core::num::traits::Zero;
    use snforge_std::signature::{KeyPairTrait, KeyPair};
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl};

    use core::poseidon::poseidon_hash_span;

    // Test accounts structure to hold all test identities
    #[derive(Drop)]
    struct TestAccounts {
        context_owner: (ContractAddress, KeyPair<felt252, felt252>),
        alice: (ContractAddress, KeyPair<felt252, felt252>),
        bob: (ContractAddress, KeyPair<felt252, felt252>),
        carol: (ContractAddress, KeyPair<felt252, felt252>),
    }

    // Context setup result structure
    #[derive(Drop)]
    struct TestContext {
        context_contract: IContextConfigsSafeDispatcher,
        context_id: context_types::ContextId,
        proxy_contract: IProxyContractSafeDispatcher,
        token: IERC20Dispatcher,
    }

    // Helper to create test accounts with known keys
    fn setup_test_accounts() -> TestAccounts {
        // Using deterministic keys from devnet
        let context_owner = KeyPairTrait::<felt252, felt252>::from_secret_key(
            0x00000000000000000000000000000000a74129f264649123f5ca7be26d2795ae.into()
        );
        let alice = KeyPairTrait::<felt252, felt252>::from_secret_key(
            0x0000000000000000000000000000000066051155b69b9b99cc8083c61653d3cd.into()
        );
        let bob = KeyPairTrait::<felt252, felt252>::from_secret_key(
            0x000000000000000000000000000000006b1ce2796be2f76852f7615ebdd854f7.into()
        );
        let carol = KeyPairTrait::<felt252, felt252>::from_secret_key(
            0x00000000000000000000000000000000d73986550f0ea6c783d53f12897d5d7d.into()
        );

        TestAccounts {
            context_owner: (context_owner.public_key.try_into().unwrap(), context_owner),
            alice: (alice.public_key.try_into().unwrap(), alice),
            bob: (bob.public_key.try_into().unwrap(), bob),
            carol: (carol.public_key.try_into().unwrap(), carol),
        }
    }

    fn deploy_context_contract(owner: ContractAddress) -> ContractAddress {
        let mut constructor_calldata = ArrayTrait::new();
        constructor_calldata.append(owner.into());
        
        let mut deployed_address: ContractAddress = 0.try_into().unwrap();
        
        match declare("ContextConfig") {
            Result::Ok(declared) => {
                match declared.contract_class().deploy(@constructor_calldata) {
                    Result::Ok((address, _)) => {
                        deployed_address = address;
                        return deployed_address;
                    },
                    Result::Err(_) => {},
                }
            },
            Result::Err(_) => {},
        };
        
        if deployed_address.is_zero() {
            panic!("Failed to deploy contract with any known name");
        }
        
        deployed_address
    }

    // Helper to setup context and proxy contracts
    fn setup_context_and_proxy() -> (TestAccounts, TestContext) {
        let accounts = setup_test_accounts();
        
        let (owner_address, owner_keypair) = accounts.context_owner;
        
        // Deploy Context Contract instead of using hardcoded address
        let context_contract_address = deploy_context_contract(owner_address);
        let context_dispatcher = IContextConfigsSafeDispatcher { contract_address: context_contract_address };

        // Setup STRK token
        let strk_address: ContractAddress = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D.try_into().unwrap();
        let strk = IERC20Dispatcher { contract_address: strk_address };

        // Create Context ID from owner's key
        let (context_high, context_low) = split_felt252(owner_keypair.public_key);
        let context_id = context_types::ContextId { high: context_high, low: context_low };

        // Deploy Proxy Contract
        let proxy_address = deploy_contract(
            "ProxyContract",
            owner_address,
            context_id,
            context_contract_address,
            strk_address
        );
        let proxy_dispatcher = IProxyContractSafeDispatcher { contract_address: proxy_address };

        // Create initial context with Alice as member
        let (_, alice_keypair) = accounts.alice.clone();
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_context_id = context_types::ContextIdentity { high: alice_high, low: alice_low };
        
        create_context_and_proxy(
            context_dispatcher,
            context_contract_address,
            context_id,
            alice_context_id,
            alice_keypair,
            0_u64,
            proxy_address,
            owner_address
        );

        // Add Bob and Carol to context
        let (_, bob_keypair) = accounts.bob.clone();
        let (bob_high, bob_low) = split_felt252(bob_keypair.public_key);
        let bob_context_id = context_types::ContextIdentity { high: bob_high, low: bob_low };

        let (_, carol_keypair) = accounts.carol.clone();
        let (carol_high, carol_low) = split_felt252(carol_keypair.public_key);
        let carol_context_id = context_types::ContextIdentity { high: carol_high, low: carol_low };

        let mut members = ArrayTrait::new();
        members.append(bob_context_id);
        members.append(carol_context_id);

        add_members_to_context(
            context_dispatcher,
            context_id,
            alice_context_id,  // Alice adds Bob and Carol
            alice_keypair,
            1_u64,  // nonce = 1 since Alice already used 0 for context creation
            members
        );

        // Return both accounts and contract setup
        (
            accounts,
            TestContext {
                context_contract: context_dispatcher,
                context_id,
                proxy_contract: proxy_dispatcher,
                token: strk,
            }
        )
    }
    // Deploy MockExternal contract
    fn deploy_mock_external() -> ContractAddress {
        match declare("MockExternal") {
            Result::Ok(declared) => {
                let mut constructor_calldata = ArrayTrait::new();
                match declared.contract_class().deploy(@constructor_calldata) {
                    Result::Ok((address, _)) => address,
                    Result::Err(err) => panic!("Failed to deploy mock contract: {:?}", err),
                }
            },
            Result::Err(err) => panic!("Failed to declare mock contract: {:?}", err),
        }
    }

    // Helper to fund a contract with tokens
    fn fund_contract(token: IERC20Dispatcher, target: ContractAddress, amount: u256) {
        let fund_address: ContractAddress = 0x2b40efa796351f7b2264301b6c73e117c6af033b41f6acf1db2b61d73d743bb.try_into().unwrap();
        start_cheat_caller_address(token.contract_address, fund_address);
        token.transfer(target, amount);
        stop_cheat_caller_address(token.contract_address);
    }

    fn deploy_contract(name: ByteArray, contract_address: ContractAddress, context_id: context_types::ContextId, context_config_account_id: ContractAddress, native_token_address: ContractAddress) -> ContractAddress {
        let mut constructor_calldata = ArrayTrait::new();
        constructor_calldata.append(contract_address.into());
        constructor_calldata.append(context_id.high);
        constructor_calldata.append(context_id.low);
        constructor_calldata.append(context_config_account_id.into());
        constructor_calldata.append(native_token_address.into());

        let declared_contract = declare(name).unwrap().contract_class();
        let (contract_address, _) = declared_contract.deploy(@constructor_calldata).unwrap();
        contract_address
    }

    fn split_felt252(value: felt252) -> (felt252, felt252) {
        // The constant 2^128 as a felt252
        let split_point: felt252 = 0x100000000000000000000000000000000.into();
        
        // Get the high part by multiplying by the inverse of split_point
        let high = value * 0x2_u128.into(); // TODO: Calculate correct inverse
        
        // Get the low part by subtracting (high * split_point) from value
        let low = value - (high * split_point);
        
        (high, low)
    }

    // Helper function to add members to context
    fn add_members_to_context(
        safe_dispatcher: IContextConfigsSafeDispatcher,
        context_id: context_types::ContextId,
        signer_id: context_types::ContextIdentity,
        signer_key_pair: snforge_std::signature::KeyPair::<core::felt252, core::felt252>,
        nonce: u64,
        members: Array<context_types::ContextIdentity>,
    ) {
        let mut request = context_types::Request {
            signer_id: signer_id.clone(),
            user_id: signer_id.clone(),
            nonce,
            kind: context_types::RequestKind::Context(
                context_types::ContextRequest {
                    context_id: context_id.clone(),
                    kind: context_types::ContextRequestKind::AddMembers(members)
                }
            )
        };

        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = poseidon_hash_span(serialized.span());
        let (r, s): (felt252, felt252) = signer_key_pair.sign(hash).unwrap();
        let signed_request: context_types::Signed = context_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => {
                println!("members added to context");
            },
            Result::Err(err) => {
                panic!("Failed to add member to context: {:?}", err);
            }
        }
    }

    fn create_context_and_proxy(
        safe_dispatcher: IContextConfigsSafeDispatcher,
        context_contract_address: ContractAddress,
        context_id: context_types::ContextId,
        alice_id: context_types::ContextIdentity,
        alice_key_pair: snforge_std::signature::KeyPair::<core::felt252, core::felt252>,
        alice_nonce: u64,
        proxy_contract_address: ContractAddress,
        owner_address: ContractAddress,
    ) {
        start_cheat_caller_address(context_contract_address, owner_address);
        
        // Get the class hash from the deployed proxy contract
        let class_hash: ClassHash = get_class_hash(proxy_contract_address);
        let native_token_address: ContractAddress = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D.try_into().unwrap();
        
        // Set the proxy contract class hash using the owner address we deployed with
        match safe_dispatcher.set_proxy_contract_class_hash(class_hash, native_token_address) {
            Result::Ok(_) => {},
            Result::Err(err) => {
                panic!("Failed to set proxy contract class hash: {:?}", err);
            }
        }

        stop_cheat_caller_address(context_contract_address);

        let request = context_types::Request {
            signer_id: alice_id.clone(),
            user_id: alice_id.clone(),
            nonce: alice_nonce,
            kind: context_types::RequestKind::Context(
                context_types::ContextRequest {
                    context_id: context_id.clone(),
                    kind: context_types::ContextRequestKind::Add((
                        alice_id.clone(),
                        context_types::Application {
                            id: context_types::ApplicationId {
                                high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
                                low: 0xe128229d757014c458e561679c42baf.into()
                            },
                            blob: context_types::ApplicationBlob {
                                high: 0x11f5f7b82d573b270a053c016cd16c20.into(),
                                low: 0xe128229d757014c458e561679c42baf.into()
                            },
                            size: 0,
                            source: "https://example.com",
                            metadata: "Test metadata",
                        }
                    ))
                }
            )
        };

        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = poseidon_hash_span(serialized.span());
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();
        let signed_request = context_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        match safe_dispatcher.mutate(signed_request) {
            Result::Ok(_) => {},
            Result::Err(err) => {
                panic!("Failed to create context: {:?}", err);
            }
        }
    }

    fn byte_array_to_felt_array(bytes: ByteArray) -> Array<felt252> {
        let mut result = ArrayTrait::new();
        let mut num_felts = 0;
        
        // First collect all the felt252s
        let mut felts = ArrayTrait::new();
        let mut i: usize = 0;
        loop {
            if i >= bytes.len() {
                break;
            }
            
            // Get 16 bytes at a time
            let mut current_felt = 0_felt252;
            let mut j = 0;
            loop {
                if j >= 16 || (i + j) >= bytes.len() {
                    break;
                }
                match bytes.at(i + j) {
                    Option::Some(byte) => {
                        // Shift left by 8 bits and add new byte
                        current_felt = current_felt * 256 + byte.into();
                    },
                    Option::None => { break; }
                };
                j += 1;
            };
            
            if j > 0 {
                felts.append(current_felt);
                num_felts += 1;
            }
            
            i += j;
        };
        
        // Add the number of felts that follow
        result.append(num_felts.into());
        
        // Add all the felt252s
        let mut i = 0;
        loop {
            if i >= felts.len() {
                break;
            }
            result.append(*felts.at(i));
            i += 1;
        };
        
        result
    }
    
    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_create_and_approve_proposal() {
        let (accounts, context) = setup_context_and_proxy();
        let proxy = context.proxy_contract;
        let mut spy = spy_events();
    
        // Get Alice's identity
        let (_, alice_keypair) = accounts.alice.clone();
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };
    
        // Create proposal ID
        let proposal_id = proxy_types::ProposalId {
            high: 0x4321_felt252,
            low: 0x8765_felt252
        };
    
        // Create a simple proposal
        let proposal = proxy_types::ProposalWithArgs {
            proposal_id: proposal_id.clone(),
            author_id: alice_id.clone(),
            actions: proxy_types::ProposalActionWithArgs::SetNumApprovals(2_u32),
        };
    
        // Create and sign the proposal
        let mut serialized = ArrayTrait::new();
        let wrapper = proxy_types::ProxyMutateRequestWrapper {
            signer_id: alice_id.clone(),
            kind: proxy_types::ProxyMutateRequest::Propose(proposal),
        };
        wrapper.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s) = alice_keypair.sign(hash).unwrap();
    
        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
    
        // Submit proposal
        match proxy.mutate(signed) {
            Result::Ok(maybe_proposal_with_approvals) => {
                let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();
    
                // Verify proposal creation events
                spy.assert_emitted(@array![
                    (proxy.contract_address, 
                    Event::ProposalCreated(proxy_types::ProposalCreated { 
                        proposal_id: proposal_id.clone(),
                        num_approvals: 1, // Alice's initial approval
                    })),
                    (proxy.contract_address,
                    Event::ProposalApproved(proxy_types::ProposalApproved {
                        proposal_id: proposal_id.clone(),
                        approver: alice_id.clone(),
                    })),
                    (proxy.contract_address,
                    Event::ProposalUpdated(proxy_types::ProposalUpdated {
                        proposal: proposal_with_approvals.clone(),
                    }))
                ]);
    
                // Get Bob's approval
                let (_, bob_keypair) = accounts.bob.clone();
                let (bob_high, bob_low) = split_felt252(bob_keypair.public_key);
                let bob_id = proxy_types::ContextIdentity { high: bob_high, low: bob_low };
    
                let request = proxy_types::ConfirmationRequestWithSigner {
                    proposal_id: proposal_id.clone(),
                    signer_id: bob_id.clone(),
                    added_timestamp: 0,
                };
    
                let mut serialized = ArrayTrait::new();
                let wrapper = proxy_types::ProxyMutateRequestWrapper {
                    signer_id: bob_id.clone(),
                    kind: proxy_types::ProxyMutateRequest::Approve(request),
                };
                wrapper.serialize(ref serialized);
    
                let hash = poseidon_hash_span(serialized.span());
                let (r, s) = bob_keypair.sign(hash).unwrap();
    
                let signed = proxy_types::Signed {
                    payload: serialized,
                    signature_r: r,
                    signature_s: s,
                };
    
                // Submit Bob's approval
                match proxy.mutate(signed) {
                    Result::Ok(maybe_proposal_with_approvals) => {
                        let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();
    
                        // Verify Bob's approval events
                        spy.assert_emitted(@array![
                            (proxy.contract_address,
                            Event::ProposalApproved(proxy_types::ProposalApproved {
                                proposal_id: proposal_id.clone(),
                                approver: bob_id.clone(),
                            })),
                            (proxy.contract_address,
                            Event::ProposalUpdated(proxy_types::ProposalUpdated {
                                proposal: proposal_with_approvals.clone(),
                            }))
                        ]);
    
                        // Verify proposal exists and has 2 approvals
                        match proxy.get_confirmations_count(proposal_id) {
                            Result::Ok(maybe_proposal) => {
                                let proposal = maybe_proposal.unwrap();
                                assert(proposal.num_approvals == 2, 'Should have 2 approvals');
                            },
                            Result::Err(err) => {
                                panic!("Failed to query proposal: {:?}", err);
                            }
                        }
                    },
                    Result::Err(err) => {
                        panic!("Failed to approve proposal with Bob: {:?}", err);
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to create proposal: {:?}", err);
            }
        };
    }

    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_deployment_setup() {
        // Setup contracts and accounts
        let (accounts, context) = setup_context_and_proxy();

        // Verify Context contract setup
        let (_, alice_keypair) = accounts.alice;
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_context_id = context_types::ContextIdentity { high: alice_high, low: alice_low };
        let is_alice_member = context.context_contract
            .has_member(context.context_id, alice_context_id)
            .unwrap();
        assert(is_alice_member, 'Alice should be a member');

        // Verify Proxy contract setup
        let num_approvals = context.proxy_contract.get_num_approvals().unwrap();
        assert(num_approvals == 3, 'num_approvals should be 3');

        // Fund and verify proxy contract balance
        let initial_balance = 1_000_000_000_000_000_000_u256;
        fund_contract(context.token, context.proxy_contract.contract_address, initial_balance);
        
        let proxy_balance = context.token
            .balance_of(context.proxy_contract.contract_address);
        assert(proxy_balance == initial_balance, 'Proxy balance incorrect');
    }

    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_set_num_approvals() {
        // Setup contracts and accounts
        let (accounts, context) = setup_context_and_proxy();
        let proxy = context.proxy_contract;

        // Test initial value
        let initial_num_approvals = proxy.get_num_approvals().unwrap();
        assert(initial_num_approvals == 3, 'Wrong initial num_approvals');

        // Get Alice's identity
        let (_, alice_keypair) = accounts.alice.clone();
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };

        // Create proposal ID
        let proposal_id = proxy_types::ProposalId {
            high: 0x4321_felt252,
            low: 0x8765_felt252
        };

        // Create the proposal
        let proposal = proxy_types::ProposalWithArgs {
            proposal_id: proposal_id.clone(),
            author_id: alice_id.clone(),
            actions: proxy_types::ProposalActionWithArgs::SetNumApprovals(2_u32),
        };

        // Create and sign the proposal
        let mut serialized = ArrayTrait::new();
        let wrapper = proxy_types::ProxyMutateRequestWrapper {
            signer_id: alice_id.clone(),
            kind: proxy_types::ProxyMutateRequest::Propose(proposal),
        };
        wrapper.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s) = alice_keypair.sign(hash).unwrap();

        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        // Submit proposal and spy on events
        let mut spy = spy_events();
        
        match proxy.mutate(signed) {
            Result::Ok(maybe_proposal_with_approvals) => {

                let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();

                 // Try to get the proposal directly to see if it exists
                let proposal = proxy.proposal(proposal_id.clone());
                
                // Verify proposal creation events
                spy.assert_emitted(@array![
                    (proxy.contract_address, 
                    Event::ProposalCreated(proxy_types::ProposalCreated { 
                        proposal_id: proposal_id.clone(),
                        num_approvals: 1, // Alice's initial approval
                    })),
                    (proxy.contract_address,
                    Event::ProposalApproved(proxy_types::ProposalApproved {
                        proposal_id: proposal_id.clone(),
                        approver: alice_id.clone(),
                    })),
                    (proxy.contract_address,
                    Event::ProposalUpdated(proxy_types::ProposalUpdated {
                        proposal: proposal_with_approvals.clone(),
                    }))
                ]);
                
                // Get Bob's approval
                let (_, bob_keypair) = accounts.bob.clone();
                let (bob_high, bob_low) = split_felt252(bob_keypair.public_key);
                let bob_id = proxy_types::ContextIdentity { high: bob_high, low: bob_low };

                let request = proxy_types::ConfirmationRequestWithSigner {
                    proposal_id: proposal_id.clone(),
                    signer_id: bob_id.clone(),
                    added_timestamp: 0,
                };

                let mut serialized = ArrayTrait::new();
                let wrapper = proxy_types::ProxyMutateRequestWrapper {
                    signer_id: bob_id.clone(),
                    kind: proxy_types::ProxyMutateRequest::Approve(request),
                };
                wrapper.serialize(ref serialized);

                let hash = poseidon_hash_span(serialized.span());
                let (r, s) = bob_keypair.sign(hash).unwrap();

                let signed = proxy_types::Signed {
                    payload: serialized,
                    signature_r: r,
                    signature_s: s,
                };

                match proxy.mutate(signed) {
                    Result::Ok(maybe_proposal_with_approvals) => {
                        let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();

                         // Try to get the proposal directly to see if it exists
                        let proposal = proxy.proposal(proposal_id.clone());

                        // Verify Bob's approval events
                        spy.assert_emitted(@array![
                            (proxy.contract_address,
                            Event::ProposalApproved(proxy_types::ProposalApproved {
                                proposal_id: proposal_id.clone(),
                                approver: bob_id.clone(),
                            })),
                            (proxy.contract_address,
                            Event::ProposalUpdated(proxy_types::ProposalUpdated {
                                proposal: proposal_with_approvals.clone(),
                            }))
                        ]);

                        // Add Carol's approval
                        let (_, carol_keypair) = accounts.carol.clone();
                        let (carol_high, carol_low) = split_felt252(carol_keypair.public_key);
                        let carol_id = proxy_types::ContextIdentity { high: carol_high, low: carol_low };

                        let request = proxy_types::ConfirmationRequestWithSigner {
                            proposal_id: proposal_id.clone(),
                            signer_id: carol_id.clone(),
                            added_timestamp: 0,
                        };

                        let mut serialized = ArrayTrait::new();
                        let wrapper = proxy_types::ProxyMutateRequestWrapper {
                            signer_id: carol_id.clone(),
                            kind: proxy_types::ProxyMutateRequest::Approve(request),
                        };
                        wrapper.serialize(ref serialized);

                        let hash = poseidon_hash_span(serialized.span());
                        let (r, s) = carol_keypair.sign(hash).unwrap();

                        let signed = proxy_types::Signed {
                            payload: serialized,
                            signature_r: r,
                            signature_s: s,
                        };

                        match proxy.mutate(signed) {
                            Result::Ok(maybe_proposal_with_approvals) => {
                                
                                // Carol's approval triggers execution, so we expect None
                                match maybe_proposal_with_approvals {
                                    Option::Some(proposal_with_approvals) => {
                                        panic!("Expected None after execution, but got Some");
                                    },
                                    Option::None => {
                                        // This is what we expect after execution
                                        
                                        // Try to get the proposal directly - should also be None since it was executed
                                        match proxy.proposal(proposal_id.clone()) {
                                            Result::Ok(maybe_proposal) => {
                                                assert(maybe_proposal.is_none(), 'Proposal should be deleted');
                                            },
                                            Result::Err(err) => {
                                                panic!("Failed to query proposal: {:?}", err);
                                            }
                                        }
                        
                                        // Verify Carol's approval and execution events
                                        spy.assert_emitted(@array![
                                            (proxy.contract_address,
                                            Event::ProposalApproved(proxy_types::ProposalApproved {
                                                proposal_id: proposal_id.clone(),
                                                approver: carol_id.clone(),
                                            })),
                                            (proxy.contract_address,
                                            Event::ProposalExecuted(proxy_types::ProposalExecuted {
                                                proposal_id: proposal_id.clone(),
                                            }))
                                        ]);
                        
                                        // Verify num_approvals was updated
                                        let final_num_approvals = proxy.get_num_approvals().unwrap();
                                        assert(final_num_approvals == 2, 'num_approvals not updated');
                                    }
                                }
                            },
                            Result::Err(err) => {
                                panic!("Failed to approve proposal with Carol: {:?}", err);
                            }
                        }
                    },
                    Result::Err(err) => {
                        panic!("Failed to approve proposal with Bob: {:?}", err);
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to create proposal: {:?}", err);
            }
        };
    }

    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_set_active_proposals_limit() {
        // Setup contracts and accounts
        let (accounts, context) = setup_context_and_proxy();
        let proxy = context.proxy_contract;

        // Test initial value
        let initial_limit = proxy.get_active_proposals_limit().unwrap();
        assert(initial_limit == 10, 'Wrong initial limit');

        // Get Alice's identity
        let (_, alice_keypair) = accounts.alice.clone();
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };

        // Create proposal ID
        let proposal_id = proxy_types::ProposalId {
            high: 0x4321_felt252,
            low: 0x8765_felt252
        };

        // Create the proposal to set new limit to 5
        let proposal = proxy_types::ProposalWithArgs {
            proposal_id: proposal_id.clone(),
            author_id: alice_id.clone(),
            actions: proxy_types::ProposalActionWithArgs::SetActiveProposalsLimit(5_u32),
        };

        // Create and sign the proposal
        let mut serialized = ArrayTrait::new();
        let wrapper = proxy_types::ProxyMutateRequestWrapper {
            signer_id: alice_id.clone(),
            kind: proxy_types::ProxyMutateRequest::Propose(proposal),
        };
        wrapper.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s) = alice_keypair.sign(hash).unwrap();

        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        // Submit proposal and spy on events
        let mut spy = spy_events();
        
        match proxy.mutate(signed) {
            Result::Ok(maybe_proposal_with_approvals) => {
                // Should get Some since this is just creation
                let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();

                // Verify proposal creation events
                spy.assert_emitted(@array![
                    (proxy.contract_address, 
                    Event::ProposalCreated(proxy_types::ProposalCreated { 
                        proposal_id: proposal_id.clone(),
                        num_approvals: 1,
                    })),
                    (proxy.contract_address,
                    Event::ProposalApproved(proxy_types::ProposalApproved {
                        proposal_id: proposal_id.clone(),
                        approver: alice_id.clone(),
                    })),
                    (proxy.contract_address,
                    Event::ProposalUpdated(proxy_types::ProposalUpdated {
                        proposal: proposal_with_approvals.clone(),
                    }))
                ]);

                // Get Bob's approval
                let (_, bob_keypair) = accounts.bob.clone();
                let (bob_high, bob_low) = split_felt252(bob_keypair.public_key);
                let bob_id = proxy_types::ContextIdentity { high: bob_high, low: bob_low };

                let request = proxy_types::ConfirmationRequestWithSigner {
                    proposal_id: proposal_id.clone(),
                    signer_id: bob_id.clone(),
                    added_timestamp: 0,
                };

                let mut serialized = ArrayTrait::new();
                let wrapper = proxy_types::ProxyMutateRequestWrapper {
                    signer_id: bob_id.clone(),
                    kind: proxy_types::ProxyMutateRequest::Approve(request),
                };
                wrapper.serialize(ref serialized);

                let hash = poseidon_hash_span(serialized.span());
                let (r, s) = bob_keypair.sign(hash).unwrap();

                let signed = proxy_types::Signed {
                    payload: serialized,
                    signature_r: r,
                    signature_s: s,
                };

                match proxy.mutate(signed) {
                    Result::Ok(maybe_proposal_with_approvals) => {
                        // Should get Some since we still need Carol's approval
                        let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();

                        // Get Carol's approval
                        let (_, carol_keypair) = accounts.carol.clone();
                        let (carol_high, carol_low) = split_felt252(carol_keypair.public_key);
                        let carol_id = proxy_types::ContextIdentity { high: carol_high, low: carol_low };

                        let request = proxy_types::ConfirmationRequestWithSigner {
                            proposal_id: proposal_id.clone(),
                            signer_id: carol_id.clone(),
                            added_timestamp: 0,
                        };

                        let mut serialized = ArrayTrait::new();
                        let wrapper = proxy_types::ProxyMutateRequestWrapper {
                            signer_id: carol_id.clone(),
                            kind: proxy_types::ProxyMutateRequest::Approve(request),
                        };
                        wrapper.serialize(ref serialized);

                        let hash = poseidon_hash_span(serialized.span());
                        let (r, s) = carol_keypair.sign(hash).unwrap();

                        let signed = proxy_types::Signed {
                            payload: serialized,
                            signature_r: r,
                            signature_s: s,
                        };

                        match proxy.mutate(signed) {
                            Result::Ok(maybe_proposal_with_approvals) => {
                                // Should be None since Carol's approval executes the proposal
                                assert(maybe_proposal_with_approvals.is_none(), 'Should be None after execution');

                                // Verify Carol's approval and execution events
                                spy.assert_emitted(@array![
                                    (proxy.contract_address,
                                    Event::ProposalApproved(proxy_types::ProposalApproved {
                                        proposal_id: proposal_id.clone(),
                                        approver: carol_id.clone(),
                                    })),
                                    (proxy.contract_address,
                                    Event::ProposalExecuted(proxy_types::ProposalExecuted {
                                        proposal_id: proposal_id.clone(),
                                    }))
                                ]);

                                // Verify proposal was executed by checking the limit
                                let final_limit = proxy.get_active_proposals_limit().unwrap();
                                assert(final_limit == 5, 'limit not updated');

                                // Verify proposal no longer exists
                                match proxy.proposal(proposal_id) {
                                    Result::Ok(maybe_proposal) => {
                                        assert(maybe_proposal.is_none(), 'Proposal should be deleted');
                                    },
                                    Result::Err(err) => {
                                        panic!("Failed to query proposal: {:?}", err);
                                    }
                                }
                            },
                            Result::Err(err) => {
                                panic!("Failed to approve proposal with Carol: {:?}", err);
                            }
                        }
                    },
                    Result::Err(err) => {
                        panic!("Failed to approve proposal with Bob: {:?}", err);
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to create proposal: {:?}", err);
            }
        };
    }

    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_external_call_without_deposit() {
        // Setup contracts and accounts
        let (accounts, context) = setup_context_and_proxy();
        let proxy = context.proxy_contract;
        
        // Deploy our mock contract
        let mock_address = deploy_mock_external();
        let mock = IMockExternalDispatcher { contract_address: mock_address };
        
        // Get initial balance from mock contract
        let initial_balance = mock.get_balance();
    
        // Get Alice's identity
        let (_, alice_keypair) = accounts.alice.clone();
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };
    
        // Create proposal ID
        let proposal_id = proxy_types::ProposalId {
            high: 0x4321_felt252,
            low: 0x8765_felt252
        };
    
        // Create calldata for increase_balance
        let mut args = ArrayTrait::new();
        let amount = 42_felt252;
        args.append(amount);

        // Create the proposal for external call
        let proposal = proxy_types::ProposalWithArgs {
            proposal_id: proposal_id.clone(),
            author_id: alice_id.clone(),
            actions: proxy_types::ProposalActionWithArgs::ExternalFunctionCall((
                mock_address,
                selector!("increase_balance"),
                0_u256,  // No deposit needed
                args,    // Pass the args directly here
            )),
        };
    
        // Create and sign the proposal
        let mut serialized = ArrayTrait::new();
        let wrapper = proxy_types::ProxyMutateRequestWrapper {
            signer_id: alice_id.clone(),
            kind: proxy_types::ProxyMutateRequest::Propose(proposal),
        };
        wrapper.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s) = alice_keypair.sign(hash).unwrap();
    
        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
    
        // Submit proposal and spy on events
        let mut spy = spy_events();
        
        match proxy.mutate(signed) {
            Result::Ok(maybe_proposal_with_approvals) => {
                // Should get Some since this is just creation
                let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();
    
                // Verify proposal creation events
                spy.assert_emitted(@array![
                    (proxy.contract_address, 
                    Event::ProposalCreated(proxy_types::ProposalCreated { 
                        proposal_id: proposal_id.clone(),
                        num_approvals: 1,
                    })),
                    (proxy.contract_address,
                    Event::ProposalApproved(proxy_types::ProposalApproved {
                        proposal_id: proposal_id.clone(),
                        approver: alice_id.clone(),
                    })),
                    (proxy.contract_address,
                    Event::ProposalUpdated(proxy_types::ProposalUpdated {
                        proposal: proposal_with_approvals.clone(),
                    }))
                ]);
    
                // Get Bob's approval
                let (_, bob_keypair) = accounts.bob.clone();
                let (bob_high, bob_low) = split_felt252(bob_keypair.public_key);
                let bob_id = proxy_types::ContextIdentity { high: bob_high, low: bob_low };
    
                let request = proxy_types::ConfirmationRequestWithSigner {
                    proposal_id: proposal_id.clone(),
                    signer_id: bob_id.clone(),
                    added_timestamp: 0,
                };
    
                let mut serialized = ArrayTrait::new();
                let wrapper = proxy_types::ProxyMutateRequestWrapper {
                    signer_id: bob_id.clone(),
                    kind: proxy_types::ProxyMutateRequest::Approve(request),
                };
                wrapper.serialize(ref serialized);
    
                let hash = poseidon_hash_span(serialized.span());
                let (r, s) = bob_keypair.sign(hash).unwrap();
    
                let signed = proxy_types::Signed {
                    payload: serialized,
                    signature_r: r,
                    signature_s: s,
                };
    
                match proxy.mutate(signed) {
                    Result::Ok(maybe_proposal_with_approvals) => {
                        // Should get Some since we still need Carol's approval
                        let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();
    
                        // Get Carol's approval
                        let (_, carol_keypair) = accounts.carol.clone();
                        let (carol_high, carol_low) = split_felt252(carol_keypair.public_key);
                        let carol_id = proxy_types::ContextIdentity { high: carol_high, low: carol_low };
    
                        let request = proxy_types::ConfirmationRequestWithSigner {
                            proposal_id: proposal_id.clone(),
                            signer_id: carol_id.clone(),
                            added_timestamp: 0,
                        };
    
                        let mut serialized = ArrayTrait::new();
                        let wrapper = proxy_types::ProxyMutateRequestWrapper {
                            signer_id: carol_id.clone(),
                            kind: proxy_types::ProxyMutateRequest::Approve(request),
                        };
                        wrapper.serialize(ref serialized);
    
                        let hash = poseidon_hash_span(serialized.span());
                        let (r, s) = carol_keypair.sign(hash).unwrap();
    
                        let signed = proxy_types::Signed {
                            payload: serialized,
                            signature_r: r,
                            signature_s: s,
                        };
    
                        match proxy.mutate(signed) {
                            Result::Ok(maybe_proposal_with_approvals) => {
                                // Should be None since Carol's approval executes the proposal
                                assert(maybe_proposal_with_approvals.is_none(), 'Should be None after execution');
                                // Verify Carol's approval and execution events
                                spy.assert_emitted(@array![
                                    (proxy.contract_address,
                                    Event::ProposalApproved(proxy_types::ProposalApproved {
                                        proposal_id: proposal_id.clone(),
                                        approver: carol_id.clone(),
                                    })),
                                    (proxy.contract_address,
                                    Event::ProposalExecuted(proxy_types::ProposalExecuted {
                                        proposal_id: proposal_id.clone(),
                                    })),
                                    (proxy.contract_address,
                                    Event::ExternalCallSuccess(proxy_types::ExternalCallSuccess {
                                        message: "External call successful"
                                    }))
                                ]);
    
                                // Verify the mock contract's balance was increased
                                let final_balance = mock.get_balance();
                                assert(final_balance == initial_balance + amount, 'Balance not increased correctly');
    
                                // Verify proposal no longer exists
                                match proxy.proposal(proposal_id) {
                                    Result::Ok(maybe_proposal) => {
                                        assert(maybe_proposal.is_none(), 'Proposal should be deleted');
                                    },
                                    Result::Err(err) => {
                                        panic!("Failed to query proposal: {:?}", err);
                                    }
                                }
                            },
                            Result::Err(err) => {
                                panic!("Failed to approve proposal with Carol: {:?}", err);
                            }
                        }
                    },
                    Result::Err(err) => {
                        panic!("Failed to approve proposal with Bob: {:?}", err);
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to create proposal: {:?}", err);
            }
        };
    }

    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_external_call_with_deposit() {
        // Setup contracts and accounts
        let (accounts, context) = setup_context_and_proxy();
        let proxy = context.proxy_contract;
        
        // Deploy our mock contract
        let mock_address = deploy_mock_external();
        let mock = IMockExternalDispatcher { contract_address: mock_address };
        
        // Get initial balances
        let initial_mock_balance = mock.get_balance();
        let deposit_amount = 1000_u256;
        
        // Fund the proxy contract with STRK
        fund_contract(context.token, proxy.contract_address, deposit_amount * 2);
        
        let initial_mock_token_balance = mock.get_token_balance(context.token.contract_address);
        let initial_proxy_token_balance = context.token.balance_of(proxy.contract_address);

        // Get Alice's identity
        let (_, alice_keypair) = accounts.alice.clone();
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };
    
        // Create proposal ID
        let proposal_id = proxy_types::ProposalId {
            high: 0x4321_felt252,
            low: 0x8765_felt252
        };
    
        // Create calldata for both increase_balance and receive_funds
        let mut args = ArrayTrait::new();
        let amount = 42_felt252;
        args.append(amount);
    
        // Create the proposal for external call with deposit
        let proposal = proxy_types::ProposalWithArgs {
            proposal_id: proposal_id.clone(),
            author_id: alice_id.clone(),
            actions: proxy_types::ProposalActionWithArgs::ExternalFunctionCall((
                mock_address,
                selector!("increase_balance"),
                deposit_amount,  // This will trigger the approval in the proxy
                args,
            )),
        };
    
        // Create and sign the proposal
        let mut serialized = ArrayTrait::new();
        let wrapper = proxy_types::ProxyMutateRequestWrapper {
            signer_id: alice_id.clone(),
            kind: proxy_types::ProxyMutateRequest::Propose(proposal),
        };
        wrapper.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s) = alice_keypair.sign(hash).unwrap();
    
        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
    
        // Submit proposal and spy on events
        let mut spy = spy_events();
        
        match proxy.mutate(signed) {
            Result::Ok(maybe_proposal_with_approvals) => {
                let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();
    
                // Get Bob's approval
                let (_, bob_keypair) = accounts.bob.clone();
                let (bob_high, bob_low) = split_felt252(bob_keypair.public_key);
                let bob_id = proxy_types::ContextIdentity { high: bob_high, low: bob_low };
    
                let request = proxy_types::ConfirmationRequestWithSigner {
                    proposal_id: proposal_id.clone(),
                    signer_id: bob_id.clone(),
                    added_timestamp: 0,
                };
    
                let mut serialized = ArrayTrait::new();
                let wrapper = proxy_types::ProxyMutateRequestWrapper {
                    signer_id: bob_id.clone(),
                    kind: proxy_types::ProxyMutateRequest::Approve(request),
                };
                wrapper.serialize(ref serialized);
    
                let hash = poseidon_hash_span(serialized.span());
                let (r, s) = bob_keypair.sign(hash).unwrap();
    
                let signed = proxy_types::Signed {
                    payload: serialized,
                    signature_r: r,
                    signature_s: s,
                };
    
                match proxy.mutate(signed) {
                    Result::Ok(maybe_proposal_with_approvals) => {
                        // Get Carol's approval
                        let (_, carol_keypair) = accounts.carol.clone();
                        let (carol_high, carol_low) = split_felt252(carol_keypair.public_key);
                        let carol_id = proxy_types::ContextIdentity { high: carol_high, low: carol_low };
    
                        let request = proxy_types::ConfirmationRequestWithSigner {
                            proposal_id: proposal_id.clone(),
                            signer_id: carol_id.clone(),
                            added_timestamp: 0,
                        };
    
                        let mut serialized = ArrayTrait::new();
                        let wrapper = proxy_types::ProxyMutateRequestWrapper {
                            signer_id: carol_id.clone(),
                            kind: proxy_types::ProxyMutateRequest::Approve(request),
                        };
                        wrapper.serialize(ref serialized);
    
                        let hash = poseidon_hash_span(serialized.span());
                        let (r, s) = carol_keypair.sign(hash).unwrap();
    
                        let signed = proxy_types::Signed {
                            payload: serialized,
                            signature_r: r,
                            signature_s: s,
                        };
    
                        match proxy.mutate(signed) {
                            Result::Ok(maybe_proposal_with_approvals) => {
                                // Should be None since Carol's approval executes the proposal
                                assert(maybe_proposal_with_approvals.is_none(), 'Should be None after execution');
    
                                // Verify final balances
                                let final_mock_token_balance = mock.get_token_balance(context.token.contract_address);
                                let final_proxy_token_balance = context.token.balance_of(proxy.contract_address);
    
                                // Verify token balances changed correctly
                                assert(
                                    final_mock_token_balance == initial_mock_token_balance + deposit_amount,
                                    'Mock token balance incorrect'
                                );
                                assert(
                                    final_proxy_token_balance == initial_proxy_token_balance - deposit_amount,
                                    'Proxy token balance incorrect'
                                );
    
                                // Verify allowance was reset to 0
                                let final_allowance = context.token.allowance(
                                    proxy.contract_address, 
                                    mock_address
                                );
                                assert(final_allowance == 0_u256, 'Allowance not reset');
    
                                // Verify events
                                spy.assert_emitted(@array![
                                    (proxy.contract_address,
                                    Event::ProposalApproved(proxy_types::ProposalApproved {
                                        proposal_id: proposal_id.clone(),
                                        approver: carol_id.clone(),
                                    })),
                                    (proxy.contract_address,
                                    Event::ProposalExecuted(proxy_types::ProposalExecuted {
                                        proposal_id: proposal_id.clone(),
                                    })),
                                    (proxy.contract_address,
                                    Event::ExternalCallSuccess(proxy_types::ExternalCallSuccess {
                                        message: "External call successful"
                                    }))
                                ]);
    
                                // Verify proposal no longer exists
                                match proxy.proposal(proposal_id) {
                                    Result::Ok(maybe_proposal) => {
                                        assert(maybe_proposal.is_none(), 'Proposal should be deleted');
                                    },
                                    Result::Err(err) => {
                                        panic!("Failed to query proposal: {:?}", err);
                                    }
                                }
                            },
                            Result::Err(err) => {
                                panic!("Failed to approve proposal with Carol: {:?}", err);
                            }
                        }
                    },
                    Result::Err(err) => {
                        panic!("Failed to approve proposal with Bob: {:?}", err);
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to create proposal: {:?}", err);
            }
        };
    }

    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_transfer_action() {
        // Setup contracts and accounts
        let (accounts, context) = setup_context_and_proxy();
        let proxy = context.proxy_contract;
        
        // Get initial balances
        let transfer_amount = 1000_u256;
        
        // Fund the proxy contract with tokens
        fund_contract(context.token, proxy.contract_address, transfer_amount * 2);
        
        // Get recipient's initial balance (we'll use Bob as recipient)
        let (bob_address, _) = accounts.bob;
        let initial_recipient_balance = context.token.balance_of(bob_address);
        let initial_proxy_balance = context.token.balance_of(proxy.contract_address);

        // Get Alice's identity for creating the proposal
        let (_, alice_keypair) = accounts.alice.clone();
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };

        // Create proposal ID
        let proposal_id = proxy_types::ProposalId {
            high: 0x4321_felt252,
            low: 0x8765_felt252
        };

        // Create the transfer proposal
        let proposal = proxy_types::ProposalWithArgs {
            proposal_id: proposal_id.clone(),
            author_id: alice_id.clone(),
            actions: proxy_types::ProposalActionWithArgs::Transfer((
                bob_address,  // recipient
                transfer_amount,  // amount
            )),
        };

        // Create and sign the proposal
        let mut serialized = ArrayTrait::new();
        let wrapper = proxy_types::ProxyMutateRequestWrapper {
            signer_id: alice_id.clone(),
            kind: proxy_types::ProxyMutateRequest::Propose(proposal),
        };
        wrapper.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s) = alice_keypair.sign(hash).unwrap();

        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        // Submit proposal and spy on events
        let mut spy = spy_events();
        
        match proxy.mutate(signed) {
            Result::Ok(maybe_proposal_with_approvals) => {
                let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();

                // Get Bob's approval
                let (_, bob_keypair) = accounts.bob.clone();
                let (bob_high, bob_low) = split_felt252(bob_keypair.public_key);
                let bob_id = proxy_types::ContextIdentity { high: bob_high, low: bob_low };

                let request = proxy_types::ConfirmationRequestWithSigner {
                    proposal_id: proposal_id.clone(),
                    signer_id: bob_id.clone(),
                    added_timestamp: 0,
                };

                let mut serialized = ArrayTrait::new();
                let wrapper = proxy_types::ProxyMutateRequestWrapper {
                    signer_id: bob_id.clone(),
                    kind: proxy_types::ProxyMutateRequest::Approve(request),
                };
                wrapper.serialize(ref serialized);

                let hash = poseidon_hash_span(serialized.span());
                let (r, s) = bob_keypair.sign(hash).unwrap();

                let signed = proxy_types::Signed {
                    payload: serialized,
                    signature_r: r,
                    signature_s: s,
                };

                match proxy.mutate(signed) {
                    Result::Ok(maybe_proposal_with_approvals) => {
                        // Get Carol's approval
                        let (_, carol_keypair) = accounts.carol.clone();
                        let (carol_high, carol_low) = split_felt252(carol_keypair.public_key);
                        let carol_id = proxy_types::ContextIdentity { high: carol_high, low: carol_low };

                        let request = proxy_types::ConfirmationRequestWithSigner {
                            proposal_id: proposal_id.clone(),
                            signer_id: carol_id.clone(),
                            added_timestamp: 0,
                        };

                        let mut serialized = ArrayTrait::new();
                        let wrapper = proxy_types::ProxyMutateRequestWrapper {
                            signer_id: carol_id.clone(),
                            kind: proxy_types::ProxyMutateRequest::Approve(request),
                        };
                        wrapper.serialize(ref serialized);

                        let hash = poseidon_hash_span(serialized.span());
                        let (r, s) = carol_keypair.sign(hash).unwrap();

                        let signed = proxy_types::Signed {
                            payload: serialized,
                            signature_r: r,
                            signature_s: s,
                        };

                        match proxy.mutate(signed) {
                            Result::Ok(maybe_proposal_with_approvals) => {
                                // Should be None since Carol's approval executes the proposal
                                assert(maybe_proposal_with_approvals.is_none(), 'Should be None after execution');

                                // Verify final balances
                                let final_recipient_balance = context.token.balance_of(bob_address);
                                let final_proxy_balance = context.token.balance_of(proxy.contract_address);

                                // Verify token balances changed correctly
                                assert(
                                    final_recipient_balance == initial_recipient_balance + transfer_amount,
                                    'Recipient balance incorrect'
                                );
                                assert(
                                    final_proxy_balance == initial_proxy_balance - transfer_amount,
                                    'Proxy balance incorrect'
                                );

                                // Verify events
                                spy.assert_emitted(@array![
                                    (proxy.contract_address,
                                    Event::ProposalApproved(proxy_types::ProposalApproved {
                                        proposal_id: proposal_id.clone(),
                                        approver: carol_id.clone(),
                                    })),
                                    (proxy.contract_address,
                                    Event::ProposalExecuted(proxy_types::ProposalExecuted {
                                        proposal_id: proposal_id.clone(),
                                    })),
                                    (proxy.contract_address,
                                    Event::TransferSuccess(proxy_types::TransferSuccess {
                                        message: "Transfer successful"
                                    }))
                                ]);

                                // Verify proposal no longer exists
                                match proxy.proposal(proposal_id) {
                                    Result::Ok(maybe_proposal) => {
                                        assert(maybe_proposal.is_none(), 'Proposal should be deleted');
                                    },
                                    Result::Err(err) => {
                                        panic!("Failed to query proposal: {:?}", err);
                                    }
                                }
                            },
                            Result::Err(err) => {
                                panic!("Failed to approve proposal with Carol: {:?}", err);
                            }
                        }
                    },
                    Result::Err(err) => {
                        panic!("Failed to approve proposal with Bob: {:?}", err);
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to create proposal: {:?}", err);
            }
        };
    }


    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_delete_proposal() {
        // Setup contracts and accounts
        let (accounts, context) = setup_context_and_proxy();
        let proxy = context.proxy_contract;
    
        // Get Alice's identity
        let (_, alice_keypair) = accounts.alice.clone();
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };
    
        // Create proposal ID
        let proposal_id = proxy_types::ProposalId {
            high: 0x4321_felt252,
            low: 0x8765_felt252
        };
    
        // Create a simple proposal
        let proposal = proxy_types::ProposalWithArgs {
            proposal_id: proposal_id.clone(),
            author_id: alice_id.clone(),
            actions: proxy_types::ProposalActionWithArgs::SetNumApprovals(2_u32),
        };
    
        // Create and sign the proposal
        let mut serialized = ArrayTrait::new();
        let wrapper = proxy_types::ProxyMutateRequestWrapper {
            signer_id: alice_id.clone(),
            kind: proxy_types::ProxyMutateRequest::Propose(proposal),
        };
        wrapper.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s) = alice_keypair.sign(hash).unwrap();
    
        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
    
        // Submit proposal and spy on events
        let mut spy = spy_events();
        
        match proxy.mutate(signed) {
            Result::Ok(maybe_proposal_with_approvals) => {
                // Should get Some since this is just creation
                let proposal_with_approvals = maybe_proposal_with_approvals.unwrap();
    
                // Verify proposal exists before deletion
                match proxy.proposal(proposal_id.clone()) {
                    Result::Ok(maybe_proposal) => {
                        assert(maybe_proposal.is_some(), 'Proposal should exist');
                    },
                    Result::Err(err) => {
                        panic!("Failed to query proposal: {:?}", err);
                    }
                }
                
                // Now create delete proposal
                let delete_proposal = proxy_types::ProposalWithArgs {
                    proposal_id: proposal_id.clone(),
                    author_id: alice_id.clone(),
                    actions: proxy_types::ProposalActionWithArgs::DeleteProposal(proposal_id.clone()),
                };

                let mut serialized = ArrayTrait::new();
                let wrapper = proxy_types::ProxyMutateRequestWrapper {
                    signer_id: alice_id.clone(),
                    kind: proxy_types::ProxyMutateRequest::Propose(delete_proposal),  // Wrap in Propose
                };
                wrapper.serialize(ref serialized);
                
                let hash = poseidon_hash_span(serialized.span());
                let (r, s) = alice_keypair.sign(hash).unwrap();
    
                let signed = proxy_types::Signed {
                    payload: serialized,
                    signature_r: r,
                    signature_s: s,
                };
    
                match proxy.mutate(signed) {
                    Result::Ok(maybe_proposal_with_approvals) => {
                        // Should be None since the proposal was deleted
                        assert(maybe_proposal_with_approvals.is_none(), 'Should be None after deletion');
    
                        // Verify proposal no longer exists
                        match proxy.proposal(proposal_id) {
                            Result::Ok(maybe_proposal) => {
                                assert(maybe_proposal.is_none(), 'Proposal should be deleted');
                            },
                            Result::Err(err) => {
                                panic!("Failed to query proposal: {:?}", err);
                            }
                        }
                    },
                    Result::Err(err) => {
                        panic!("Failed to delete proposal: {:?}", err);
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to create proposal: {:?}", err);
            }
        }
    }

    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_context_variable_change() {
        // Setup contracts and accounts
        let (accounts, context) = setup_context_and_proxy();
        let proxy = context.proxy_contract;
        let mut spy = spy_events();

        // Get identities for Alice, Bob, and Carol
        let (_, alice_keypair) = accounts.alice.clone();
        let (alice_high, alice_low) = split_felt252(alice_keypair.public_key);
        let alice_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };

        let (_, bob_keypair) = accounts.bob.clone();
        let (bob_high, bob_low) = split_felt252(bob_keypair.public_key);
        let bob_id = proxy_types::ContextIdentity { high: bob_high, low: bob_low };

        let (_, carol_keypair) = accounts.carol.clone();
        let (carol_high, carol_low) = split_felt252(carol_keypair.public_key);
        let carol_id = proxy_types::ContextIdentity { high: carol_high, low: carol_low };

        // Create a proposal to set a context variable
        let proposal_id = proxy_types::ProposalId { high: 0x1234_felt252, low: 0x5678_felt252 };
        
        // Create key-value pair for the context
        let mut key = ArrayTrait::new();
        key.append('test_key');
        let mut value = ArrayTrait::new();
        value.append('test_value');

        let proposal = proxy_types::ProposalWithArgs {
            proposal_id: proposal_id.clone(),
            author_id: alice_id.clone(),
            actions: proxy_types::ProposalActionWithArgs::SetContextValue((key.clone(), value.clone())),
        };

        // Create and sign the proposal with Alice
        let mut serialized = ArrayTrait::new();
        let wrapper = proxy_types::ProxyMutateRequestWrapper {
            signer_id: alice_id.clone(),
            kind: proxy_types::ProxyMutateRequest::Propose(proposal),
        };
        wrapper.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s) = alice_keypair.sign(hash).unwrap();

        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        // Submit the proposal
        match proxy.mutate(signed) {
            Result::Ok(proposal_with_approvals) => {
                // Verify proposal creation event
                spy.assert_emitted(@array![
                    (proxy.contract_address,
                    Event::ProposalCreated(proxy_types::ProposalCreated {
                        proposal_id: proposal_id.clone(),
                        num_approvals: 1, // Alice's approval as author
                    }))
                ]);

                // Get Bob's approval
                let approval_request = proxy_types::ConfirmationRequestWithSigner {
                    proposal_id: proposal_id.clone(),
                    signer_id: bob_id.clone(),
                    added_timestamp: 0_u64,
                };

                let mut serialized = ArrayTrait::new();
                let wrapper = proxy_types::ProxyMutateRequestWrapper {
                    signer_id: bob_id.clone(),
                    kind: proxy_types::ProxyMutateRequest::Approve(approval_request),
                };
                wrapper.serialize(ref serialized);
                
                let hash = poseidon_hash_span(serialized.span());
                let (r, s) = bob_keypair.sign(hash).unwrap();

                let signed = proxy_types::Signed {
                    payload: serialized,
                    signature_r: r,
                    signature_s: s,
                };

                match proxy.mutate(signed) {
                    Result::Ok(_) => {
                        // Get Carol's approval to reach threshold
                        let approval_request = proxy_types::ConfirmationRequestWithSigner {
                            proposal_id: proposal_id.clone(),
                            signer_id: carol_id.clone(),
                            added_timestamp: 0_u64,
                        };

                        let mut serialized = ArrayTrait::new();
                        let wrapper = proxy_types::ProxyMutateRequestWrapper {
                            signer_id: carol_id.clone(),
                            kind: proxy_types::ProxyMutateRequest::Approve(approval_request),
                        };
                        wrapper.serialize(ref serialized);
                        
                        let hash = poseidon_hash_span(serialized.span());
                        let (r, s) = carol_keypair.sign(hash).unwrap();

                        let signed = proxy_types::Signed {
                            payload: serialized,
                            signature_r: r,
                            signature_s: s,
                        };

                        match proxy.mutate(signed) {
                            Result::Ok(_) => {
                                // Verify the context value was set
                                match proxy.get_context_value(key) {
                                    Result::Ok(maybe_value) => {
                                        assert(maybe_value.is_some(), 'Value should exist');
                                        let stored_value = maybe_value.unwrap();
                                        assert(stored_value.len() == value.len(), 'Wrong value length');
                                        
                                        let mut i = 0;
                                        loop {
                                            if i >= value.len() {
                                                break;
                                            }
                                            assert(stored_value.at(i) == value.at(i), 'Wrong value content');
                                            i += 1;
                                        }
                                    },
                                    Result::Err(err) => {
                                        panic!("Failed to get context value: {:?}", err);
                                    }
                                }

                                // Verify all events were emitted
                                spy.assert_emitted(@array![
                                    (proxy.contract_address,
                                    Event::ProposalApproved(proxy_types::ProposalApproved {
                                        proposal_id: proposal_id.clone(),
                                        approver: bob_id.clone(),
                                    })),
                                    (proxy.contract_address,
                                    Event::ProposalApproved(proxy_types::ProposalApproved {
                                        proposal_id: proposal_id.clone(),
                                        approver: carol_id.clone(),
                                    })),
                                    (proxy.contract_address,
                                    Event::SetContextValueSuccess(proxy_types::SetContextValueSuccess {
                                        message: "Set context value successful"
                                    }))
                                ]);
                            },
                            Result::Err(err) => {
                                panic!("Failed to approve proposal with Carol: {:?}", err);
                            }
                        }
                    },
                    Result::Err(err) => {
                        panic!("Failed to approve proposal with Bob: {:?}", err);
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to create proposal: {:?}", err);
            }
        };
    }
}