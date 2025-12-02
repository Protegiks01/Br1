# NoVulnerability found for this question.

## Reasoning

After thorough validation against the Brix Money Protocol framework, this claim falls under **centralization risks**, which are **explicitly out of scope** per the README.

### Why This Is Out of Scope

The README states clearly: [1](#0-0) 

The core issue here is about **admin privilege architecture** - specifically, whether admins should have emergency rescue functions. While framed as "missing functionality," this is fundamentally a **centralization design decision**:

1. **The recommended fix is an `onlyOwner` rescue function** - This adds admin privilege, which is a centralization consideration
2. **The "vulnerability" is lack of admin power** - The claim argues admins need MORE control to rescue user funds
3. **Operational errors are admin responsibility** - Peer misconfiguration and contract upgrades are admin actions

### Additional Concerns

**Known Issue Similarity:**
The Zellic audit already identified message delivery failures causing fund loss: [2](#0-1) 

While this specific contract isn't mentioned, the underlying issue of "failed LayerZero operations leading to fund loss" is within the known problem space.

**Threat Model Violation:**
The scenarios described require:
- Admin peer misconfiguration (admin operational error)
- Contract upgrades/destruction (admin or protocol decisions)  
- L2 chain issues (external infrastructure assumed reliable per threat model)

**Design Pattern - Not a Bug:**
The `wiTryOFTAdapter` inherits directly from LayerZero's `OFTAdapter` without modifications: [3](#0-2) 

This is a **deliberate minimal wrapper pattern**. The protocol chose to use LayerZero's standard OFTAdapter without custom rescue logic. Other contracts (iTryTokenOFT, VaultComposer, UnstakeMessenger) serve different purposes with different risk profiles, justifying their rescue functions.

**LayerZero V2 Design:**
LayerZero V2 provides retry mechanisms and executor configurations. "Permanent failures" typically indicate configuration issues that admins must resolve at the infrastructure level, not through contract rescue functions.

### Notes

This is a **design decision** about emergency admin privileges, not a vulnerability. The protocol must choose between:
- **Option A**: Minimal trust, no admin rescue (current design for OFTAdapter)
- **Option B**: Emergency powers, admin can rescue (design for other contracts)

Different contracts make different choices based on their role and risk profile. Reporting this as a security vulnerability conflates design philosophy with exploitable flaws. The proper venue for this concern is protocol design review, not a security audit focused on exploitable vulnerabilities.

### Citations

**File:** README.md (L27-29)
```markdown
### Centralization Risks

Any centralization risks are out-of-scope for the purposes of this audit contest.
```

**File:** README.md (L40-40)
```markdown
- Native fee loss on failed `wiTryVaultComposer.LzReceive` execution. In the case of underpayment, users will lose their fee and will have to pay twice to complete the unstake request.
```

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L26-33)
```text
contract wiTryOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for wiTryOFTAdapter
     * @param _token Address of the wiTRY share token from StakedUSDe
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```
