#[cfg(test)]
mod tests {

    use starknet::{
        ContractAddress, 
    };
    use snforge_std::{
        declare, ContractClassTrait, DeclareResultTrait, 
        // start_cheat_caller_address, stop_cheat_caller_address, EventSpyAssertionsTrait, spy_events,
    };

    use proxy_contract::{
        IProxyContractSafeDispatcher,
        IProxyContractSafeDispatcherTrait,
        // IProxyContractDispatcher,
        // IProxyContractDispatcherTrait,
    };

    use proxy_contract::types::{Proposal, Signed, ContextIdentity, ProposalAction, ContextId};

    use core::traits::Into;
    use core::array::ArrayTrait;
    // use core::clone::Clone;
    use core::byte_array::ByteArray;

    use snforge_std::signature::KeyPairTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl};

    use core::poseidon::poseidon_hash_span;

    fn deploy_contract(name: ByteArray, contract_address: ContractAddress, context_id: ContextId, context_config_account_id: ContractAddress) -> ContractAddress {
    
        let mut constructor_calldata = ArrayTrait::new();
        constructor_calldata.append(contract_address.into());
        constructor_calldata.append(context_id.into());
        constructor_calldata.append(context_config_account_id.into());

        let contract = declare(name).unwrap().contract_class();
        let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
        contract_address
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn test_create_and_approve_proposal() {

        let contract_felt: felt252 = 0x1ee8c80f0572f8fac06ff78c13031659dadc2a339f328729dc9d5767c3fd5e0.into();
        let contract_address: ContractAddress = contract_felt.try_into().unwrap();

        let context_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let context_public_key = context_key_pair.public_key;
        let context_id = context_public_key;

        let node1 = KeyPairTrait::<felt252, felt252>::generate();
        let node1_public_key = node1.public_key;
        let node1_id: ContractAddress = node1_public_key.try_into().unwrap();

        let contract_address = deploy_contract("ProxyContract", node1_id, context_id, contract_address);

        let safe_dispatcher = IProxyContractSafeDispatcher { contract_address };

        let alice_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let alice_public_key = alice_key_pair.public_key;
        let alice_id = alice_public_key;
        let mut alice_nonce = 0;

        let bob_key_pair = KeyPairTrait::<felt252, felt252>::generate();
        let bob_public_key = bob_key_pair.public_key;
        let bob_id = bob_public_key;
        let mut bob_nonce = 0;

        let proposal = Proposal {
            receiver_id: contract_address,
            author_id: alice_id,
            actions: ProposalAction::FunctionCall(
                (
                    0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into(), 
                    0x11f5f7b82d573b270a053c016cd16c20e128229d757014c458e561679c42baf.into()
                )
            ),
        };
        
        let mut serialized = ArrayTrait::new();
        proposal.serialize(ref serialized);
        
        let hash = poseidon_hash_span(serialized.span());
        let (r, s): (felt252, felt252) = alice_key_pair.sign(hash).unwrap();

        let signed = Signed {
            payload: serialized,
            signature_r: r,
            signature_s: s,
        };
        match safe_dispatcher.create_and_approve_proposal(signed) {
            Result::Ok(_) => panic!("Should have panicked"),
            Result::Err(panic_data) => {
                println!("panic_data: {:?}", panic_data);
                assert(*panic_data.at(0) == 'signer_id equals context_id', *panic_data.at(0));
            }
        };
    }
}