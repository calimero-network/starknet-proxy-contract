# Starknet Proxy Contract

## Overview
The **Proxy Contract** is a key component in Calimero contexts, deployed by the **Context Contract**. It serves as the logical layer for executing web3 requests such as cross-contract calls, fund transfers, and creating/updating its own configuration values. All actions in the Proxy Contract are governed by a proposal and voting mechanism, ensuring collective decision-making within the context.

The Proxy Contract interacts with the Context Contract to verify user permissions and roles. Once a proposal receives enough votes from context members, its action is executed automatically. For actions requiring funds (e.g., transfers or cross-contract calls), **users must ensure the Proxy Contract is adequately funded.**

## Features
- **Proposal Mechanism**: Allows users to create proposals for various actions, including:
  - Cross-contract calls
  - Fund transfers
  - Default configuration variables updates
  - Adding/Updating new variables
- **Voting System**: Ensures proposals are approved collectively by context members.
- **Integration with Context Contract**: Verifies proposal creators and approvers are members of the associated context.
- **Automated Execution**: Executes approved proposals automatically. - **If the contract doesn't have necessary funds to execute the proposal action it will remove the proposal and users will need to create new proposal with same action**
- **User-Funded Actions**: Requires users to fund the Proxy Contract for actions involving resource allocation.

## Setup Instructions

### Prerequisites
1. Ensure the following tools are installed using `asdf`:
   - `scarb`
   - `starknet-devnet`
   - `starknet-foundry`
2. Current dependecies versions:
   ```
   scarb - 2.8.4
   starknet-devnet - 0.2.0-rc.3
   starknet-foundry - 0.31.0
   ```
3. Start the `starknet-devnet` environment:
   ```bash
   starknet-devnet --seed 12344
   ```

### Declaring Contract
Declare the Proxy Contract:
```bash
sncast --account devnet declare --url http://127.0.0.1:5050/rpc --fee-token strk --contract-name ProxyContract
```

### Deploying Contract
The Proxy Contract is deployed automatically by the Context Contract during the creation of a new Calimero context. For details, refer to the [Context Contract repository](https://github.com/calimero-network/starknet-context-contract).

### Linking with Context Contract
The Proxy Contract relies on the Context Contract for user verification and governance. For proper setup, the Proxy Contract must be declared before linking, as described in the Context Contract setup instructions.

## Testing Instructions

### Running Tests

### Note
**The variable changes are needed since Proxy contract checks if members are users of Context created by Context Contract**

1. Start the `starknet-devnet` environment:
   ```bash
   starknet-devnet --seed 12344
   ```
2. Declare and deploy the Proxy Contract as described in the setup steps.
3. Context contract needs to be deployed and contain proxy contract class hash for tests to work
4. Change Context contract address variable `context_contract_felt` in `test/test_contract.cairo` file to match the deployed context contract address
5. Change Proxy contract address hash variable `class_hash` in `test/test_contract.cairo` in `create_context_and_proxy()` function
3. Run the tests:
   ```bash
   snforge test
   ```

### Test Coverage
Tests are located in the `tests/test_proxy_contract.cairo` file and cover:
- Creation of proposals.
- Approval of proposals.
- Verifying permissions for proposal creation and approval.
- Testing multiple types of proposal actions.
- Setting and verifying configuration variables.

### Notes
- User keys and necessary data are retrieved from the `starknet-devnet` environment.
- Ensure all dependencies and the devnet environment are properly configured before running the tests.

## Miscellaneous
- **Funding Requirement**: For actions involving fund transfers or cross-contract calls, users must ensure the Proxy Contract is funded.
- **Heavely dependent on [Context Contract](https://github.com/calimero-network/starknet-context-contract).**
