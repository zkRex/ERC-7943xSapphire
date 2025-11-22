# Privacy Analysis: ERC-7943 Implementation on Sapphire

## Executive Summary

Your implementation has **several critical privacy issues** that need to be addressed to properly leverage Sapphire's confidential computing features. While the contracts correctly use encrypted state (automatic on Sapphire), they leak private information through:

1. **Public Events**: All events (transfers, freezes, whitelist changes) are plaintext and publicly visible
2. **Public Queryability**: All view functions are publicly accessible without authentication - anyone can query balances, ownership, whitelist status, freeze amounts, and role assignments
3. **Storage Access Patterns**: Transfer patterns are visible to compute nodes through storage access traces
4. **Gas/Timing Side Channels**: Conditional branches leak information through gas usage

**The system provides encrypted storage but complete public observability and queryability**, which defeats the purpose of confidential computing for RWA tokens.

## Critical Issues

### 1. Events Leak Private Information [CRITICAL]

**Problem**: Contract logs/events are **NOT encrypted** on Sapphire. All events are publicly visible and leak sensitive information.

**Current Issues**:

#### Inherited Transfer Events
Your contracts inherit from OpenZeppelin's `ERC20`, `ERC721`, and `ERC1155`, which automatically emit `Transfer` events containing:
- `from` address (sender)
- `to` address (receiver)  
- `amount` or `tokenId` (transfer details)

**Example from uRWA20**:
```solidity
// Inherited from ERC20 - automatically emitted on transfers
event Transfer(address indexed from, address indexed to, uint256 value);
```

#### Custom Events Also Leak Information
Your custom events expose sensitive data:

**uRWA20**:
- `event ForcedTransfer(address indexed from, address indexed to, uint256 amount)` - leaks forced transfer details
- `event Frozen(address indexed account, uint256 amount)` - leaks freeze amounts
- `event Whitelisted(address indexed account, bool status)` - leaks whitelist status

**uRWA721**:
- `event ForcedTransfer(address indexed from, address indexed to, uint256 indexed tokenId)` - leaks forced transfers
- `event Frozen(address indexed account, uint256 indexed tokenId, bool indexed frozenStatus)` - leaks freeze status

**uRWA1155**:
- Similar events with tokenId and amount

**Impact**: 
- Transfer history is completely public
- Freeze amounts/status are public
- Whitelist status is public
- Forced transfers are public

**Recommendation**: 
According to [Sapphire documentation](https://docs.oasis.io/build/sapphire/develop/concept#contract-logs), you should:
1. **Remove or modify Transfer events** - Fork OpenZeppelin contracts and remove/modify the Transfer event emissions
2. **Use encrypted events** - Use Sapphire precompiles to encrypt sensitive data before emitting events
3. **Consider access-controlled getters** - Instead of events, use access-controlled view functions for authorized parties

**Reference**: 
> "Unmodified contracts may leak state through logs. Base contracts like those provided by OpenZeppelin often emit logs containing private information. If you don't know they're doing that, you might undermine the confidentiality of your state."

### 2. Public Queryability: View Functions Expose Private State [HIGH]

**Problem**: Public view functions expose private state to anyone, defeating the purpose of confidential computing. **Anyone can query sensitive information without authentication**, making the system publicly queryable despite encrypted storage.

**Current Issues**:

#### ERC-7943 Specific Functions (All Contracts):
- `canTransact(address)` - exposes whitelist status (public)
- `canTransfer(...)` - exposes transfer permissions (public)
- `getFrozenTokens(...)` - exposes frozen amounts/status (public)

#### Inherited ERC-20 Functions (uRWA20):
- `balanceOf(address)` - exposes token balances (public)
- `totalSupply()` - exposes total token supply (public)
- `allowance(address owner, address spender)` - exposes approval amounts (public)

#### Inherited ERC-721 Functions (uRWA721):
- `balanceOf(address)` - exposes number of tokens owned (public)
- `ownerOf(uint256 tokenId)` - exposes token ownership (public)
- `tokenURI(uint256 tokenId)` - exposes token metadata URI (public)
- `getApproved(uint256 tokenId)` - exposes token approvals (public)
- `isApprovedForAll(address owner, address operator)` - exposes operator approvals (public)

#### Inherited ERC-1155 Functions (uRWA1155):
- `balanceOf(address account, uint256 id)` - exposes token balances (public)
- `balanceOfBatch(address[] accounts, uint256[] ids)` - exposes multiple balances in one call (public)
- `uri(uint256 id)` - exposes token metadata URI (public)
- `isApprovedForAll(address account, address operator)` - exposes operator approvals (public)

#### Inherited AccessControl Functions (All Contracts):
- `hasRole(bytes32 role, address account)` - exposes role assignments (public)
- `getRoleMember(bytes32 role, uint256 index)` - exposes role members (public)
- `getRoleMemberCount(bytes32 role)` - exposes role membership counts (public)

**Impact**: 
- **Complete public queryability**: Anyone can query balances, freeze status, whitelist status, token ownership, approvals, and role assignments
- **No privacy for sensitive RWA data**: Token holdings, KYC status (via whitelist), and freeze amounts are completely transparent
- **Defeats the privacy benefits of Sapphire**: While state is encrypted, all information is accessible through public view functions
- **Enables surveillance**: Observers can build complete profiles of token holders and their activities

**Recommendation**:
1. **Add access control** - Restrict view functions to authorized parties using `onlyRole` modifiers
2. **Use view-call authentication** - Implement signed view calls for authenticated access
3. **Consider removing public view functions** - Replace with access-controlled getters

**Reference**: 
> "The `from` address using of calls is derived from a signature attached to the call. Unsigned calls have their sender set to the zero address. This allows contract authors to write getters that release secrets to authenticated callers (e.g. by checking the `msg.sender` value), but without requiring a transaction to be posted on-chain."

### 3. Storage Access Patterns Leak Information [MEDIUM]

**Problem**: While storage values are encrypted, the **access patterns** (which storage slots are accessed) are visible to compute nodes.

**Current Issues**:
- Direct storage access in `_update` hooks reveals which accounts are involved in transfers
- No obfuscation of storage access patterns
- Storage size is not hidden (though values are encrypted)

**Impact**:
- Observers can infer transfer patterns from storage access
- Can trace transfers from sender to receiver addresses

**Recommendation**:
1. **Consider ORAM** - Use Oblivious RAM implementations to obfuscate access patterns
2. **Constant-time operations** - Ensure operations take constant time regardless of private data
3. **Pad storage** - Use constant-size storage layouts where possible

**Reference**:
> "Contract state leaks a fine-grained access pattern. Contract state is backed by an encrypted key-value store. However, the trace of encrypted records is leaked to the compute node. As a concrete example, an ERC-20 token transfer would leak which encrypted record is for the sender's account balance and which is for the receiver's account balance. Such a token would be traceable from sender address to receiver address."

### 4. Gas and Timing Side Channels [MEDIUM]

**Problem**: Gas usage and execution time can leak information about private data through side channels.

**Current Issues**:
- Conditional branches based on private data (whitelist status, frozen amounts)
- Different gas costs for different code paths
- No gas padding for branches dependent on private data

**Recommendation**:
1. **Use `Sapphire.padGas`** - Pad gas usage for branches that depend on private data
2. **Constant-time operations** - Ensure all branches take the same time/gas
3. **Review conditional logic** - Minimize branches based on private state

**Reference**:
> "You should be aware that taking actions based on the value of private data may leak the private data through side channels like time spent, gas use and accessed memory locations. If you need to branch on private data, you should in most cases ensure that both branches exhibit the same time/gas and storage patterns."

## What's Working Well

### 1. Encrypted State
- Using `mapping` for state (not `immutable` or `constant`)
- State will be automatically encrypted on Sapphire
- No sensitive data stored in bytecode

### 2. Testing Setup
- Using `@oasisprotocol/sapphire-hardhat` for encrypted transactions
- Testing on `sapphire-localnet`
- Proper network configuration

### 3. Transaction Encryption
- Hardhat config includes Sapphire provider
- Transactions will be encrypted automatically

## Recommendations

### Immediate Actions (Critical)

1. **Remove or Encrypt Transfer Events**
   ```solidity
   // Option 1: Override _update to suppress Transfer events
   function _update(...) internal override {
       // ... your logic ...
       // Don't call super._update() to avoid Transfer event
       // Or emit a modified/encrypted event instead
   }
   
   // Option 2: Use Sapphire precompiles to encrypt event data
   import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
   
   event EncryptedTransfer(bytes32 encryptedData);
   
   function _update(...) internal override {
       // ... logic ...
       bytes32 encrypted = Sapphire.encrypt(abi.encode(from, to, amount));
       emit EncryptedTransfer(encrypted);
   }
   ```

2. **Add Access Control to View Functions**
   ```solidity
   function balanceOf(address account) public view override onlyRole(VIEWER_ROLE) returns (uint256) {
       return super.balanceOf(account);
   }
   
   function getFrozenTokens(address account) public view override onlyRole(VIEWER_ROLE) returns (uint256) {
       return _frozenTokens[account];
   }
   ```

3. **Remove or Encrypt Custom Events**
   - Remove `ForcedTransfer`, `Frozen`, `Whitelisted` events OR
   - Encrypt sensitive data before emitting

### Medium Priority

4. **Implement View-Call Authentication**
   - Use signed view calls for authenticated access
   - Allow zero-address calls for public information only

5. **Add Gas Padding**
   ```solidity
   import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
   
   function _update(...) internal override {
       if (privateCondition) {
           // ... logic ...
       } else {
           // ... logic ...
       }
       Sapphire.padGas(); // Ensure constant gas usage
   }
   ```

6. **Consider Storage Obfuscation**
   - Research ORAM implementations
   - Consider constant-size storage layouts

## Testing Privacy Features

Your current tests don't verify privacy. Consider adding:

1. **Event Privacy Tests**
   ```typescript
   it("Should not emit unencrypted Transfer events", async function () {
       // Verify events are encrypted or suppressed
   });
   ```

2. **View Function Access Control Tests**
   ```typescript
   it("Should revert view calls from unauthorized addresses", async function () {
       // Test that view functions require proper roles
   });
   ```

3. **Storage Access Pattern Tests**
   ```typescript
   it("Should obfuscate storage access patterns", async function () {
       // Verify constant-time operations
   });
   ```

## References

- [Sapphire vs Ethereum](https://docs.oasis.io/build/sapphire/ethereum)
- [Sapphire Concepts](https://docs.oasis.io/build/sapphire/develop/concept)
- [Sapphire Security](https://docs.oasis.io/build/sapphire/develop/security)
- [Sapphire Testing](https://docs.oasis.io/build/sapphire/develop/testing)

## Conclusion

While your implementation correctly uses Sapphire's encrypted state and transaction features, **it leaks significant private information through events and public view functions**. The system suffers from **complete public queryability** - anyone can query all sensitive information without authentication.

### Summary of Privacy Leaks:

1. **Public Observability** (via Events):
   - All transfers, freezes, whitelist changes, and forced transfers are publicly visible in logs
   - Transfer history is completely transparent

2. **Public Queryability** (via View Functions):
   - All token balances, ownership, approvals, and metadata are publicly queryable
   - Whitelist status, freeze amounts, and role assignments are publicly accessible
   - No authentication required for any view function

3. **Storage Access Patterns** (via compute node visibility):
   - Transfer patterns can be inferred from storage access traces
   - Sender/receiver relationships are traceable

4. **Gas/Timing Side Channels**:
   - Conditional branches leak information through gas usage patterns

### Required Actions:

1. Remove or encrypt Transfer events
2. Add access control to **all** view functions (balanceOf, ownerOf, getFrozenTokens, canTransact, etc.)
3. Remove or encrypt custom events (ForcedTransfer, Frozen, Whitelisted)
4. Consider storage access pattern obfuscation
5. Add gas padding for private data branches

The current implementation provides **confidential state** but **public observability and public queryability**, which completely undermines privacy for RWA tokens. To achieve true privacy on Sapphire, you must restrict both event emissions and view function access.

