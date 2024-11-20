#[cfg(test)]
mod tests {

    use starknet::{
        ContractAddress, 
        ClassHash,
    };
    use snforge_std::{
        declare,
        ContractClassTrait,
        DeclareResultTrait, 
        start_cheat_caller_address,
        stop_cheat_caller_address,
        EventSpyAssertionsTrait,
        spy_events,
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

    use core::traits::Into;
    use core::array::ArrayTrait;
    use core::array::SpanTrait;
    use core::byte_array::ByteArray;
    use core::byte_array::ByteArrayTrait;
    use core::option::OptionTrait;
    use core::result::ResultTrait;

    use snforge_std::signature::KeyPairTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl};

    use core::poseidon::poseidon_hash_span;

    fn deploy_contract(name: ByteArray, contract_address: ContractAddress, context_id: context_types::ContextId, context_config_account_id: ContractAddress) -> ContractAddress {
        let mut constructor_calldata = ArrayTrait::new();
        constructor_calldata.append(contract_address.into());
        // Append context_id high and low separately
        constructor_calldata.append(context_id.high);
        constructor_calldata.append(context_id.low);
        constructor_calldata.append(context_config_account_id.into());
    
        let contract = declare(name).unwrap().contract_class();
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
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

    // #[test]
    // #[feature("safe_dispatcher")]
    // #[fork("devnet")]
    // fn test_create_and_approve_proposal() {

    //     let context_contract_felt: felt252 = 0x7cdd9d6ec666ad0954705f25f86e8adf064ae789ef34f042cba7e52e40536bb.into();
    //     let context_contract_address: ContractAddress = context_contract_felt.try_into().unwrap();
    //     let context_config_dispatcher = IContextConfigsSafeDispatcher { contract_address: context_contract_address };
    //     // 9. account in devnet
    //     let context_key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(0x00000000000000000000000000000000a74129f264649123f5ca7be26d2795ae.into());
    //     let context_public_key = context_key_pair.public_key;
    //     let (context_high, context_low) = split_felt252(context_public_key);
    //     let context_id = context_types::ContextId { high: context_high, low: context_low };

    //     println!("context_id: {:?}", context_id);
    //     println!("context high: {:?}", context_high);
    //     println!("context low: {:?}", context_low);

    //     let node1 = KeyPairTrait::<felt252, felt252>::generate();
    //     let node1_public_key = node1.public_key;
    //     let node1_id: ContractAddress = node1_public_key.try_into().unwrap();

    //     let proxy_contract_address = deploy_contract("ProxyContract", node1_id, context_id, context_contract_address);
    //     println!("proxy_contract_address: {:?}", proxy_contract_address);

    //     let safe_dispatcher = IProxyContractSafeDispatcher { contract_address: proxy_contract_address };
    //     let spy_dispatcher = IProxyContractDispatcher { contract_address: proxy_contract_address };
    //     let mut spy = spy_events();

    //     // 10. account in devnet
    //     let alice_key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(0x0000000000000000000000000000000066051155b69b9b99cc8083c61653d3cd.into());
    //     let alice_public_key = alice_key_pair.public_key;
    //     let (alice_high, alice_low) = split_felt252(alice_public_key);
    //     let alice_proxy_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };
    //     let alice_context_id = context_types::ContextIdentity { high: alice_high, low: alice_low };

    //     // 7. account in devnet
    //     let bob_key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(0x000000000000000000000000000000006b1ce2796be2f76852f7615ebdd854f7.into());
    //     let bob_public_key = bob_key_pair.public_key;
    //     let (bob_high, bob_low) = split_felt252(bob_public_key);
    //     let bob_proxy_id = proxy_types::ContextIdentity { high: bob_high, low: bob_low };
    //     let bob_context_id = context_types::ContextIdentity { high: bob_high, low: bob_low };

    //     // 8. account in devnet
    //     let carol_key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(0x00000000000000000000000000000000d73986550f0ea6c783d53f12897d5d7d.into());
    //     let carol_public_key = carol_key_pair.public_key;
    //     let (carol_high, carol_low) = split_felt252(carol_public_key);
    //     let carol_proxy_id = proxy_types::ContextIdentity { high: carol_high, low: carol_low };
    //     let carol_context_id = context_types::ContextIdentity { high: carol_high, low: carol_low };

    //     // Create context with Alice first
    //     create_context_and_proxy(
    //         context_config_dispatcher,
    //         context_contract_address,
    //         context_id,
    //         alice_context_id,
    //         alice_key_pair,
    //         0_u64,
    //         proxy_contract_address
    //     );

    //     // Add Bob to context
    //     add_members_to_context(
    //         context_config_dispatcher,
    //         context_id,
    //         alice_context_id, // Alice is adding Bob
    //         alice_key_pair,
    //         1_u64, // increment nonce
    //         array![bob_context_id.clone(), carol_context_id.clone()]
    //     );

    //     // STRK token transfer contract 
    //     let strk_address: ContractAddress = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D.try_into().unwrap();
    //     let strk = IERC20Dispatcher { contract_address: strk_address };
        
    //     let fund_address: ContractAddress = 0x2b40efa796351f7b2264301b6c73e117c6af033b41f6acf1db2b61d73d743bb.try_into().unwrap();
    //     println!("Fund address: {:?}", fund_address);

    //     // Get and print all relevant addresses
    //     let proxy_balance = strk.balance_of(proxy_contract_address);
    //     println!("Proxy contract STRK balance: {}", proxy_balance);

    //     // Try to transfer from caller to proxy
    //     start_cheat_caller_address(strk_address, fund_address);
    //     strk.transfer(proxy_contract_address, 1_000_000_000_000_000_000_u256);
    //     stop_cheat_caller_address(strk_address);

    //     // Check balances after transfer
    //     let proxy_balance_after = strk.balance_of(proxy_contract_address);
    //     println!("Proxy contract STRK balance after transfer: {}", proxy_balance_after);

    //     let proposal = proxy_types::ProposalWithArgs {
    //         proposal_id: 0,
    //         author_id: alice_proxy_id,
    //         actions: proxy_types::ProposalActionWithArgs::Transfer(
    //             (
    //                 // 5. account in devnet
    //                 0x4169c2daf88e2cb8c2563bd15a02d989207613c09d4347a4374c00e62b06dff.try_into().unwrap(),
    //                 1_000_000_000_000_000_000_u256,
    //                 // STRK token contract address
    //                 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D.try_into().unwrap()
    //             )
    //         ),
    //     };
        
    //     let mut serialized = ArrayTrait::new();
    //     proposal.serialize(ref serialized);
        
    //     let hash = poseidon_hash_span(serialized.span());
    //     let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();

    //     let signed = proxy_types::Signed {
    //         payload: serialized,
    //         signature_r: r,
    //         signature_s: s,
    //     };
    //     let mut proposal_id = 0;
    //     match safe_dispatcher.create_and_approve_proposal(signed) {
    //         Result::Ok(proposal_with_approvals) => {
    //             println!("proposal created");
    //             println!("proposal_with_approvals: {:?}", proposal_with_approvals);
    //             proposal_id = proposal_with_approvals.proposal_id;
    //         },
    //         Result::Err(panic_data) => {
    //             println!("panic_data: {:?}", panic_data);
    //             assert(*panic_data.at(0) == 'signer_id equals context_id', *panic_data.at(0));
    //         }
    //     };

    //     let request = proxy_types::ConfirmationRequestWithSigner {
    //         proposal_id,
    //         signer_id: bob_proxy_id,
    //         added_timestamp: 0,
    //     };

    //     let mut serialized = ArrayTrait::new();
    //     request.serialize(ref serialized);
    //     let hash = poseidon_hash_span(serialized.span());
    //     let (r, s): (felt252, felt252) = bob_key_pair.sign(hash).unwrap();

    //     let signed = proxy_types::Signed {
    //         payload: serialized,
    //         signature_r: r,
    //         signature_s: s,
    //     };

    //     match safe_dispatcher.approve(signed) {
    //         Result::Ok(proposal_with_approvals) => {
    //             println!("proposal confirmed");
    //             println!("proposal_with_approvals: {:?}", proposal_with_approvals);
    //         },
    //         Result::Err(panic_data) => {
    //             println!("panic_data: {:?}", panic_data);
    //         }
    //     };
        
    //     let recipient: ContractAddress = 0x4169c2daf88e2cb8c2563bd15a02d989207613c09d4347a4374c00e62b06dff.try_into().unwrap();
    //     let balance_before = strk.balance_of(recipient);
    //     println!("Recipient balance before: {}", balance_before);

    //     // After Bob's approval, add Carol's approval
    //     let request = proxy_types::ConfirmationRequestWithSigner {
    //         proposal_id,
    //         signer_id: carol_proxy_id,
    //         added_timestamp: 0,
    //     };

    //     let mut serialized = ArrayTrait::new();
    //     request.serialize(ref serialized);
    //     let hash = poseidon_hash_span(serialized.span());
    //     let (r, s): (felt252, felt252) = carol_key_pair.sign(hash).unwrap();

    //     let signed = proxy_types::Signed {
    //         payload: serialized,
    //         signature_r: r,
    //         signature_s: s,
    //     };
        
    //     let _ = spy_dispatcher.approve(signed);

    //     spy.assert_emitted(
    //         @array![
    //             (
    //                 proxy_contract_address,
    //                 Event::TransferSuccess(proxy_types::TransferSuccess { message: "Transfer successful" })
    //             )
    //         ]
    //     );

    //     // Check balance after all approvals
    //     let balance_after = strk.balance_of(recipient);
    //     println!("Recipient balance after: {}", balance_after);
    //     assert(balance_after == balance_before + 1_000_000_000_000_000_000_u256, 'Transfer failed');

    // }

    #[test]
    #[feature("safe_dispatcher")]
    #[fork("devnet")]
    fn test_create_context_variable_values() {

        let context_contract_felt: felt252 = 0x7cdd9d6ec666ad0954705f25f86e8adf064ae789ef34f042cba7e52e40536bb.into();
        let context_contract_address: ContractAddress = context_contract_felt.try_into().unwrap();
        let context_config_dispatcher = IContextConfigsSafeDispatcher { contract_address: context_contract_address };
        // 9. account in devnet
        let context_key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(0x00000000000000000000000000000000a74129f264649123f5ca7be26d2795ae.into());
        let context_public_key = context_key_pair.public_key;
        let (context_high, context_low) = split_felt252(context_public_key);
        let context_id = context_types::ContextId { high: context_high, low: context_low };

        let node1 = KeyPairTrait::<felt252, felt252>::generate();
        let node1_public_key = node1.public_key;
        let node1_id: ContractAddress = node1_public_key.try_into().unwrap();

        let proxy_contract_address = deploy_contract("ProxyContract", node1_id, context_id, context_contract_address);
        println!("proxy_contract_address: {:?}", proxy_contract_address);

        let safe_dispatcher = IProxyContractSafeDispatcher { contract_address: proxy_contract_address };
        let spy_dispatcher = IProxyContractDispatcher { contract_address: proxy_contract_address };
        let mut spy = spy_events();

        // 10. account in devnet
        let alice_key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(0x0000000000000000000000000000000066051155b69b9b99cc8083c61653d3cd.into());
        let alice_public_key = alice_key_pair.public_key;
        let (alice_high, alice_low) = split_felt252(alice_public_key);
        let alice_proxy_id = proxy_types::ContextIdentity { high: alice_high, low: alice_low };
        let alice_context_id = context_types::ContextIdentity { high: alice_high, low: alice_low };

        // 7. account in devnet
        let bob_key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(0x000000000000000000000000000000006b1ce2796be2f76852f7615ebdd854f7.into());
        let bob_public_key = bob_key_pair.public_key;
        let (bob_high, bob_low) = split_felt252(bob_public_key);
        let bob_proxy_id = proxy_types::ContextIdentity { high: bob_high, low: bob_low };
        let bob_context_id = context_types::ContextIdentity { high: bob_high, low: bob_low };

        // 8. account in devnet
        let carol_key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(0x00000000000000000000000000000000d73986550f0ea6c783d53f12897d5d7d.into());
        let carol_public_key = carol_key_pair.public_key;
        let (carol_high, carol_low) = split_felt252(carol_public_key);
        let carol_proxy_id = proxy_types::ContextIdentity { high: carol_high, low: carol_low };
        let carol_context_id = context_types::ContextIdentity { high: carol_high, low: carol_low };

        // Create context with Alice first
        create_context_and_proxy(
            context_config_dispatcher,
            context_contract_address,
            context_id,
            alice_context_id,
            alice_key_pair,
            0_u64,
            proxy_contract_address
        );

        // Add Bob to context
        add_members_to_context(
            context_config_dispatcher,
            context_id,
            alice_context_id, // Alice is adding Bob
            alice_key_pair,
            1_u64, // increment nonce
            array![bob_context_id.clone(), carol_context_id.clone()]
        );

        // STRK token transfer contract 
        let strk_address: ContractAddress = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D.try_into().unwrap();
        let strk = IERC20Dispatcher { contract_address: strk_address };
        
        let fund_address: ContractAddress = 0x2b40efa796351f7b2264301b6c73e117c6af033b41f6acf1db2b61d73d743bb.try_into().unwrap();

        // Try to transfer from caller to proxy
        start_cheat_caller_address(strk_address, fund_address);
        strk.transfer(proxy_contract_address, 1_000_000_000_000_000_000_u256);
        stop_cheat_caller_address(strk_address);

        // Test context key and value
        let test_key = "thisistestkeyforusage123";
        let test_value = "thisisvalueforsomeusageinthecontextparttesting312#";
        // Convert strings to felt arrays
        let key_array = byte_array_to_felt_array(test_key);
        let value_array = byte_array_to_felt_array(test_value);

        println!("key_array: {:?}", key_array);
        println!("value_array: {:?}", value_array);

        // Create the storage proposal
        let storage_proposal = proxy_types::ProposalWithArgs {
            proposal_id: 0,
            author_id: alice_proxy_id,
            actions: proxy_types::ProposalActionWithArgs::SetContextValue(
                (key_array.clone(), value_array.clone())
            ),
        };
        
        let mut serialized = ArrayTrait::new();
        storage_proposal.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();

        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
        let mut proposal_id = 0;
        match safe_dispatcher.create_and_approve_proposal(signed) {
            Result::Ok(proposal_with_approvals) => {
                println!("proposal created");
                println!("proposal_with_approvals: {:?}", proposal_with_approvals);
                proposal_id = proposal_with_approvals.proposal_id;
            },
            Result::Err(panic_data) => {
                println!("panic_data: {:?}", panic_data);
                assert(*panic_data.at(0) == 'signer_id equals context_id', *panic_data.at(0));
            }
        };

        let request = proxy_types::ConfirmationRequestWithSigner {
            proposal_id,
            signer_id: bob_proxy_id,
            added_timestamp: 0,
        };

        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = poseidon_hash_span(serialized.span());
        let (r, s): (felt252, felt252) = bob_key_pair.sign(hash).unwrap();

        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };

        match safe_dispatcher.approve(signed) {
            Result::Ok(proposal_with_approvals) => {
                println!("proposal confirmed");
                println!("proposal_with_approvals: {:?}", proposal_with_approvals);
            },
            Result::Err(panic_data) => {
                println!("panic_data: {:?}", panic_data);
            }
        };

        // After Bob's approval, add Carol's approval
        let request = proxy_types::ConfirmationRequestWithSigner {
            proposal_id,
            signer_id: carol_proxy_id,
            added_timestamp: 0,
        };

        let mut serialized = ArrayTrait::new();
        request.serialize(ref serialized);
        let hash = poseidon_hash_span(serialized.span());
        let (r, s): (felt252, felt252) = carol_key_pair.sign(hash).unwrap();

        let signed = proxy_types::Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
        
        let _ = spy_dispatcher.approve(signed);

        spy.assert_emitted(
            @array![
                (
                    proxy_contract_address,
                    Event::SetContextValueSuccess(proxy_types::SetContextValueSuccess { message: "Set context value successful" })
                )
            ]
        );

        // After the proposal is approved, verify the context value was set correctly
        match safe_dispatcher.get_context_value(key_array.clone()) {
            Result::Ok(stored_value_opt) => {
                match stored_value_opt {
                    Option::Some(stored_value) => {
                        println!("stored_value: {:?}", stored_value);
                        assert(stored_value.len() == value_array.len(), 'Wrong value length');
                        let mut i = 0;
                        loop {
                            if i >= stored_value.len() {
                                break;
                            }
                            assert(*stored_value.at(i) == *value_array.at(i), 'Wrong value at index');
                            i += 1;
                        };
                        println!("Context value verified successfully");
                    },
                    Option::None => {
                        panic!("Context value not found");
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to get context value: {:?}", err);
            }
        };

        // Try getting a non-existent key
        let non_existent_key = byte_array_to_felt_array("nonexistentkey");
        match safe_dispatcher.get_context_value(non_existent_key) {
            Result::Ok(stored_value_opt) => {
                match stored_value_opt {
                    Option::Some(stored_value) => {
                        // For non-existent key, we should get an empty array
                        assert(stored_value.len() == 0, 'Should be empty array');
                        println!("Correctly returned empty array for non-existent key");
                    },
                    Option::None => {
                        println!("Correctly returned None for non-existent key");
                    }
                }
            },
            Result::Err(err) => {
                panic!("Failed to get non-existent key: {:?}", err);
            }
        };

        // Test context_storage_entries
        match safe_dispatcher.context_storage_entries(0, 10) {
            Result::Ok(entries) => {
                println!("Storage entries found: {:?}", entries);
                
                // Should have at least one entry (our test key-value pair)
                assert(entries.len() > 0, 'No entries found');
                
                // Check if our test key-value pair is in the entries
                let mut found = false;
                let mut i = 0;
                loop {
                    if i >= entries.len() {
                        break;
                    }
                    
                    let (stored_key, stored_value) = entries.at(i);
                    
                    // Compare key and value arrays
                    if stored_key.len() == key_array.len() {
                        let mut key_matches = true;
                        let mut j = 0;
                        loop {
                            if j >= stored_key.len() {
                                break;
                            }
                            if *stored_key.at(j) != *key_array.at(j) {
                                key_matches = false;
                                break;
                            }
                            j += 1;
                        };
                        
                        if key_matches {
                            // If key matches, verify value
                            assert(stored_value.len() == value_array.len(), 'Wrong value length');
                            let mut j = 0;
                            loop {
                                if j >= stored_value.len() {
                                    break;
                                }
                                assert(*stored_value.at(j) == *value_array.at(j), 'Wrong value at index');
                                j += 1;
                            };
                            found = true;
                            break;
                        }
                    }
                    
                    i += 1;
                };
                
                assert(found, 'key-value pair not found');
                println!("Context storage entries verified successfully");
            },
            Result::Err(err) => {
                panic!("Failed to get context storage entries: {:?}", err);
            }
        };

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
    ) {
        // 4. account in devnet
        let owner: ContractAddress = 0x342b2bdb2060f9c11179b96061d8b12d0941fbee2709cac9197eb537ad1a0bd.try_into().unwrap();
        start_cheat_caller_address(context_contract_address, owner);

        // Devnet proxy contract class hash
        let class_hash: ClassHash = 0xc3e2459943574a078bbe325919ac42647c2933289040a4423f62b925762bb7.try_into().unwrap();
        // Set the proxy contract class hash - devnet
        match safe_dispatcher.set_proxy_contract_class_hash(class_hash) {
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
    
}