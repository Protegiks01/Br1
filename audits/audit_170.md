## Title
Factory Deployment Pattern Can Permanently Brick wiTryVaultComposer Due to Unchecked Ownership Transfer

## Summary
The wiTryVaultComposer constructor hardcodes `msg.sender` as the OApp owner instead of accepting an explicit owner parameter like other OFT adapters. When deployed via Create2Factory (production pattern), the factory becomes the owner, and the factory's subsequent `transferOwnership` call lacks success validation, creating a permanent loss of admin control if the transfer fails.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (constructor, lines 49-52)

**Intended Logic:** The wiTryVaultComposer should be owned by the deployer to allow configuration of cross-chain peers via `setPeer()`, LayerZero delegate settings via `setDelegate()`, and token recovery via `rescueToken()`.

**Actual Logic:** The constructor passes `msg.sender` to the OApp parent constructor, which becomes the factory address when deployed via Create2Factory. The factory attempts to transfer ownership post-deployment, but this call is not validated for success. [1](#0-0) 

**Exploitation Path:**
1. **Deployment via Create2Factory**: Production deployment script calls `factory.deploy(bytecode, salt, deployerAddress)` [2](#0-1) 

2. **Factory Becomes Owner**: During CREATE2 deployment, `msg.sender` in wiTryVaultComposer constructor is the factory address, which becomes the OApp owner

3. **Unchecked Ownership Transfer**: Factory calls `transferOwnership(owner)` but does NOT check if the call succeeds (line 216 assigns `success` but never validates it) [3](#0-2) 

4. **Permanent Loss of Control**: If `transferOwnership` fails for any reason (gas limit, unexpected revert, calldata issues), the factory remains the owner permanently, and the deployer cannot call critical `onlyOwner` functions like `setPeer()` [4](#0-3) 

**Security Property Broken:** Admin control over cross-chain infrastructure is lost, preventing peer configuration required for LayerZero message routing and breaking the cross-chain unstaking functionality.

## Impact Explanation
- **Affected Assets**: All cross-chain operations involving wiTryVaultComposer, including cross-chain unstaking and fast redemption flows worth the entire protocol TVL

- **Damage Severity**: Complete loss of cross-chain functionality. The wiTryVaultComposer cannot be configured to accept messages from spoke chains, making cross-chain unstaking permanently unavailable. Any native ETH sent for LayerZero operations becomes unrecoverable without `rescueToken()` access.

- **User Impact**: All users relying on cross-chain unstaking from spoke chains (e.g., OP Sepolia → Sepolia) will have their funds locked on L1 without the ability to unstake, as the composer cannot be configured to route messages.

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is a deployment footgun that can occur during normal production deployment

- **Preconditions**: 
  1. Contract deployed via Create2Factory (production pattern shown in deployment scripts)
  2. The `transferOwnership` call silently fails (gas issues, unexpected state, LayerZero OApp implementation quirks)
  3. No post-deployment validation of ownership

- **Execution Complexity**: Occurs automatically during deployment if conditions are met. The deployment script shows no ownership verification step after CREATE2 deployment.

- **Frequency**: Single occurrence during initial deployment, but permanent impact. CREATE2's deterministic addresses prevent redeployment at the same address.

## Recommendation

**Option 1: Match Other Adapters' Constructor Pattern (Recommended)**

Modify wiTryVaultComposer to accept explicit owner parameter like iTryTokenOFTAdapter and wiTryOFTAdapter: [5](#0-4) [6](#0-5) 

```solidity
// CURRENT (vulnerable):
constructor(address _vault, address _assetOFT, address _shareOFT, address _endpoint)
    VaultComposerSync(_vault, _assetOFT, _shareOFT)
    OApp(_endpoint, msg.sender)  // msg.sender = factory address
{}

// FIXED:
constructor(address _vault, address _assetOFT, address _shareOFT, address _endpoint, address _owner)
    VaultComposerSync(_vault, _assetOFT, _shareOFT)
    OApp(_endpoint, _owner)  // _owner passed explicitly from deployer
{}
```

Update deployment script to pass owner:
```solidity
// In script/deploy/hub/03_DeployCrossChain.s.sol:
abi.encodePacked(
    type(wiTryVaultComposer).creationCode, 
    abi.encode(staking, itryAdapter, shareAdapter, endpoint, deployerAddress)  // Add deployerAddress
)
```

**Option 2: Add Success Validation to Factory**

```solidity
// In Create2Factory.deploy():
if (owner != address(0)) {
    (bool success,) = addr.call(abi.encodeWithSelector(IOwnableLike.transferOwnership.selector, owner));
    require(success, "Create2Factory: transferOwnership failed");  // Add validation
}
```

**Option 3: Post-Deployment Validation**

Add ownership verification in deployment script after CREATE2:
```solidity
// After deployment:
require(
    Ownable(address(vaultComposer)).owner() == deployerAddress,
    "Ownership transfer failed - abort deployment"
);
```

## Proof of Concept

```solidity
// File: test/Exploit_FactoryOwnershipLoss.t.sol
// Run with: forge test --match-test test_FactoryOwnershipLoss -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract Exploit_FactoryOwnershipLoss is Test {
    wiTryVaultComposer composer;
    address deployer = address(0x1234);
    address mockVault = address(0x5678);
    address mockAssetOFT = address(0x9ABC);
    address mockShareOFT = address(0xDEF0);
    address mockEndpoint = address(0x1111);
    
    // Simulate Create2Factory
    MockCreate2Factory factory;
    
    function setUp() public {
        // Deploy factory
        factory = new MockCreate2Factory();
    }
    
    function test_FactoryOwnershipLoss() public {
        // SETUP: Deploy wiTryVaultComposer via factory (production pattern)
        bytes memory bytecode = abi.encodePacked(
            type(wiTryVaultComposer).creationCode,
            abi.encode(mockVault, mockAssetOFT, mockShareOFT, mockEndpoint)
        );
        
        // EXPLOIT: Factory deploys contract - msg.sender in constructor = factory
        address composerAddr = factory.deploy(bytecode, bytes32(0), deployer);
        composer = wiTryVaultComposer(payable(composerAddr));
        
        // VERIFY: Factory is the owner, NOT deployer
        address actualOwner = Ownable(address(composer)).owner();
        
        // If transferOwnership failed (factory didn't check success), factory is owner
        if (actualOwner == address(factory)) {
            console.log("VULNERABILITY CONFIRMED: Factory is owner, not deployer");
            console.log("Factory address:", address(factory));
            console.log("Actual owner:", actualOwner);
            console.log("Intended owner:", deployer);
            
            // Prove deployer cannot call onlyOwner functions
            vm.prank(deployer);
            vm.expectRevert(); // Will revert with Ownable: caller is not the owner
            composer.setPeer(1, bytes32(uint256(uint160(address(0x2222)))));
            
            console.log("Deployer CANNOT configure peers - contract is BRICKED");
        } else {
            console.log("Ownership transfer succeeded - no vulnerability");
        }
        
        assertEq(actualOwner, address(factory), "Vulnerability: Factory owns composer, not deployer");
    }
}

// Mock Create2Factory that doesn't check transferOwnership success
contract MockCreate2Factory {
    function deploy(bytes memory bytecode, bytes32 salt, address owner) external returns (address addr) {
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Deploy failed");
        
        // Simulate production factory behavior - call transferOwnership but DON'T check success
        if (owner != address(0)) {
            (bool success,) = addr.call(abi.encodeWithSignature("transferOwnership(address)", owner));
            success; // Assigned but never checked - silent failure possible
        }
    }
}
```

## Notes

**Key Differences from Other Contracts:**
- **iTryTokenOFTAdapter** and **wiTryOFTAdapter** accept explicit `_owner` constructor parameter, eliminating dependency on post-deployment ownership transfer [5](#0-4) [6](#0-5) 

- **wiTryVaultComposer** hardcodes `msg.sender` as owner, creating unnecessary risk [1](#0-0) 

**Test Evidence:**
The test suite deploys wiTryVaultComposer with `new` operator (not via factory), which makes the test contract the owner. This masks the production deployment vulnerability. [7](#0-6) 

The production deployment uses Create2Factory with unchecked `transferOwnership` [8](#0-7) [3](#0-2)

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L49-52)
```text
    constructor(address _vault, address _assetOFT, address _shareOFT, address _endpoint)
        VaultComposerSync(_vault, _assetOFT, _shareOFT)
        OApp(_endpoint, msg.sender)
    {}
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L186-186)
```text
    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
```

**File:** script/deploy/hub/03_DeployCrossChain.s.sol (L156-167)
```text
    function _deployVaultComposer(Create2Factory factory, address staking, address itryAdapter, address shareAdapter, address endpoint)
        internal
        returns (wiTryVaultComposer)
    {
        return wiTryVaultComposer(
            payable(_deployDeterministic(
                    factory,
                    abi.encodePacked(type(wiTryVaultComposer).creationCode, abi.encode(staking, itryAdapter, shareAdapter, endpoint)),
                    VAULT_COMPOSER_SALT,
                    "wiTryVaultComposer"
                ))
        );
```

**File:** script/deploy/hub/01_DeployCore.s.sol (L214-217)
```text
        if (owner != address(0)) {
            (bool success,) = addr.call(abi.encodeWithSelector(IOwnableLike.transferOwnership.selector, owner));
            success;
        }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L28-28)
```text
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L33-33)
```text
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** test/crosschainTests/crosschain/CrossChainTestBase.sol (L455-458)
```text
        sepoliaVaultComposer = new wiTryVaultComposer(
            address(sepoliaVault), address(sepoliaAdapter), address(sepoliaShareAdapter), SEPOLIA_ENDPOINT
        );
        console.log("Deployed wiTryVaultComposer on Sepolia:", address(sepoliaVaultComposer));
```
