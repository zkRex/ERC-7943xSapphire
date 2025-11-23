# Privacy Analysis: ERC-7943 Implementation on Sapphire

## Executive Summary

**Status: MOSTLY FIXED** - Significant improvements have been made, but one critical issue remains.

Your implementation has made **substantial progress** in addressing privacy concerns. Most critical issues have been resolved:

**FIXED**: View functions now require `VIEWER_ROLE` access control  
**FIXED**: Custom events are now encrypted using Sapphire precompiles  
**FIXED**: Gas padding added to prevent side-channel leakage  

**REMAINING ISSUE**: Standard Transfer events from OpenZeppelin are still being emitted in plaintext, leaking transfer information.

**The system now provides encrypted storage, access-controlled queryability, and encrypted custom events, but still leaks transfer information through standard Transfer events.**

## Critical Issues

### 1. Events Leak Private Information [CRITICAL - PARTIALLY FIXED]

**Status**: Custom events are now encrypted , but standard Transfer events still leak information 
**Fixed**: 
-  Custom events (`EncryptedTransfer`, `EncryptedWhitelisted`, `EncryptedFrozen`, `EncryptedForcedTransfer`) are now encrypted using `Sapphire.encrypt()`
-  Encryption key is generated in constructor using `Sapphire.randomBytes()`
-  Nonce counter ensures uniqueness of encrypted events

**Remaining Issue**: Standard Transfer Events Still Emitted

Your contracts still call `super._update()` which emits the standard `Transfer` events from OpenZeppelin:

**uRWA20** (line 268):
```solidity
super._update(from, to, amount); // Emits Transfer(address indexed from, address indexed to, uint256 value)
```

**uRWA721** (line 285):
```solidity
super._update(to, tokenId, auth); // Emits Transfer(address indexed from, address indexed to, uint256 indexed tokenId)
```

**uRWA1155** (line 305):
```solidity
super._update(from, to, ids, values); // Emits TransferSingle/TransferBatch events
```

**Impact**: 
-  Transfer history is still publicly visible through standard Transfer events
-  `from`, `to`, and `amount`/`tokenId` are exposed in plaintext logs
-  Custom encrypted events provide additional privacy, but don't replace the standard events

**Root Cause: OpenZeppelin v5 Uses Private State Variables**

The fundamental issue is that **OpenZeppelin v5 uses `private` visibility for internal state variables** (`_balances`, `_owners`, `_totalSupply`), which means:
-  Cannot access `_balances[account]` directly from child contracts
-  Cannot manually update balances without calling parent functions
-  Must call `super._update()` to update balances, which emits Transfer events
-  Cannot override `_mint`/`_burn` without emitting events because parent functions emit them

**Solution: Use Solmate Instead of OpenZeppelin**

**Solmate** (or its successor **Solady**) provides a better alternative for privacy-preserving contracts:

**Advantages of Solmate:**
-  **Public state variables**: `balanceOf` and `totalSupply` are `public` mappings/variables
-  **Direct access**: Can read/write `balanceOf[account]` and `totalSupply` directly
-  **No forced events**: Can override `_mint`, `_burn`, `transfer`, `transferFrom` without calling parent
-  **Gas efficient**: More optimized than OpenZeppelin
-  **Simpler structure**: No hidden `private` state that blocks access

**Implementation Options:**

1. **Use Solmate as Library (Recommended)**
   ```bash
   pnpm add solmate
   # or
   pnpm add solady  # Solmate's successor, actively maintained
   ```
   
   **Pros:**
   - Easy to update if library receives fixes
   - Standard dependency management
   - Can use `import {ERC20} from "solmate/tokens/ERC20.sol";`
   
   **Cons:**
   - Dependency on external package
   - Need to ensure version compatibility

2. **Copy Solmate Files Manually**
   - Copy ERC20.sol, ERC721.sol, ERC1155.sol into your `contracts/lib/` directory
   - Modify imports to use local copies
   
   **Pros:**
   - Full control over the code
   - No external dependencies
   - Can make custom modifications if needed
   
   **Cons:**
   - Manual updates if you want to pull in fixes
   - More code to maintain

**Recommendation**: 
Use **Solady** (Solmate's successor) as a library dependency. It's actively maintained and provides the same benefits as Solmate. Then override `_mint`, `_burn`, `transfer`, and `transferFrom` to update balances directly without emitting Transfer events.

**Reference**: 
> "Unmodified contracts may leak state through logs. Base contracts like those provided by OpenZeppelin often emit logs containing private information. If you don't know they're doing that, you might undermine the confidentiality of your state."

**Library vs Manual Copy Decision:**

**Recommendation: Use Solady as Library Dependency**

**Why Library (Recommended):**
-  Easy dependency management: `pnpm add solady`
-  Can receive security updates and bug fixes via package updates
-  Standard import syntax: `import {ERC20} from "solady/tokens/ERC20.sol";`
-  Less code to maintain in your repository
-  Solady is actively maintained (Solmate is not)

**When to Copy Manually:**
- If you need to make custom modifications to the base contracts
- If you want to avoid any external dependencies
- If you need to ensure a specific version is always used
- If you're building a completely self-contained system

**Implementation Steps for Library Approach:**
1. Remove OpenZeppelin: `pnpm remove @openzeppelin/contracts`
2. Install Solady: `pnpm add solady`
3. Update all imports in your contracts
4. Override `_mint`, `_burn`, `transfer`, `transferFrom` to update `balanceOf` directly
5. Emit only encrypted events, never call `super` functions that emit Transfer events

### 2. Public Queryability: View Functions Expose Private State [FIXED ]

**Status**:  **RESOLVED** - All view functions now require `VIEWER_ROLE` access control

**Fixed Implementation**:

All view functions now require `VIEWER_ROLE` and reject unauthenticated calls:

**uRWA20** (examples):
```solidity
function balanceOf(address account) public view override returns (uint256) {
    require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
    return super.balanceOf(account);
}

function canTransact(address account) public view override returns (bool allowed) {
    require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
    allowed = _isWhitelisted(account);
}
```

**uRWA721** and **uRWA1155**: Similar access control on all view functions.

**Impact**: 
-  **No public queryability**: Only authorized parties with `VIEWER_ROLE` can query sensitive information
-  **Privacy protected**: Token balances, ownership, whitelist status, and freeze amounts are now access-controlled
-  **Proper use of Sapphire**: View-call authentication works correctly - unsigned calls have `msg.sender == address(0)` and are rejected

**Note**: The `VIEWER_ROLE` must be granted to authorized parties. Consider implementing a role management system for granting/revoking viewer access.

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

### 4. Gas and Timing Side Channels [FIXED ]

**Status**:  **RESOLVED** - Gas padding added to prevent side-channel leakage

**Fixed Implementation**:

All `_update` hooks now include gas padding:

**uRWA20** (line 278):
```solidity
Sapphire.padGas(200000); // Pad gas to prevent side-channel leakage
```

**uRWA721** (line 295):
```solidity
Sapphire.padGas(200000); // Estimate worst-case gas: ~150k for transfer with all checks and encryption
```

**uRWA1155** (line 315):
```solidity
Sapphire.padGas(250000); // Estimate worst-case gas: ~200k for batch transfer with all checks and encryption
```

**Impact**: 
-  **Constant gas usage**: Gas padding ensures operations take consistent gas regardless of private data values
-  **Side-channel protection**: Conditional branches based on whitelist status, frozen amounts, etc. no longer leak information through gas usage
-  **Proper implementation**: Gas padding values appear to be based on worst-case estimates

**Note**: Ensure gas padding values are sufficient to cover all code paths. Consider profiling actual gas usage to verify padding amounts.

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

1. **Switch from OpenZeppelin to Solmate/Solady**  **REMAINING ISSUE**
   
   **Why OpenZeppelin Can't Be Used:**
   - OpenZeppelin v5 uses `private` visibility for `_balances`, `_owners`, `_totalSupply`
   - Cannot access these directly from child contracts
   - Must call `super._update()` which emits Transfer events
   - Cannot override without emitting events
   
   **Solution: Migrate to Solmate/Solady**
   
   **Step 1: Install Solady (Recommended - actively maintained)**
   ```bash
   pnpm add solady
   ```
   
   Or install Solmate (no longer actively maintained):
   ```bash
   pnpm add solmate
   ```
   
   **Step 2: Update Imports**
   ```solidity
   // Replace:
   import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
   
   // With:
   import {ERC20} from "solady/tokens/ERC20.sol";
   // or
   import {ERC20} from "solmate/tokens/ERC20.sol";
   ```
   
   **Step 3: Override Functions Without Calling Parent**
   
   **For ERC20:**
   ```solidity
   import {ERC20} from "solady/tokens/ERC20.sol";
   
   contract uRWA20 is ERC20, AccessControlEnumerable, IERC7943Fungible {
       // ... existing code ...
       
       function _mint(address to, uint256 amount) internal override {
           // Update balances directly (balanceOf is public in Solmate/Solady)
           totalSupply += amount;
           unchecked {
               balanceOf[to] += amount;
           }
           // Don't call super._mint() - that would emit Transfer event
           // Emit only encrypted event
           bytes memory plaintext = abi.encode(address(0), to, amount, _eventNonce++);
           bytes32 nonce = bytes32(_eventNonce);
           bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
           emit EncryptedTransfer(encrypted);
       }
       
       function _burn(address from, uint256 amount) internal override {
           balanceOf[from] -= amount;
           unchecked {
               totalSupply -= amount;
           }
           // Emit only encrypted event
           bytes memory plaintext = abi.encode(from, address(0), amount, _eventNonce++);
           bytes32 nonce = bytes32(_eventNonce);
           bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
           emit EncryptedTransfer(encrypted);
       }
       
       function transfer(address to, uint256 amount) public override returns (bool) {
           // Your custom transfer logic with whitelist checks
           require(_isWhitelisted(msg.sender), ERC7943CannotTransact(msg.sender));
           require(_isWhitelisted(to), ERC7943CannotTransact(to));
           // ... frozen token checks ...
           
           // Update balance directly
           balanceOf[msg.sender] -= amount;
           unchecked {
               balanceOf[to] += amount;
           }
           
           // Emit only encrypted event
           bytes memory plaintext = abi.encode(msg.sender, to, amount, _eventNonce++);
           bytes32 nonce = bytes32(_eventNonce);
           bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
           emit EncryptedTransfer(encrypted);
           
           Sapphire.padGas(200000);
           return true;
       }
       
       function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
           // Similar implementation - update balances directly, emit only encrypted event
       }
   }
   ```
   
   **For ERC721 and ERC1155:**
   - Similar pattern: override `_mint`, `_burn`, and transfer functions
   - Update `balanceOf`, `ownerOf` (ERC721), or `balanceOf[account][id]` (ERC1155) directly
   - Emit only encrypted events, not standard Transfer events
   
   **Alternative: Copy Files Manually**
   - If you prefer not to use a library dependency, copy Solmate/Solady contract files into `contracts/lib/`
   - Modify imports to use local copies: `import {ERC20} from "./lib/ERC20.sol";`
   - Gives full control but requires manual updates

### Completed Actions 
2.  **Access Control Added to View Functions** - All view functions now require `VIEWER_ROLE`

3.  **Custom Events Encrypted** - All custom events use `Sapphire.encrypt()`

4.  **Gas Padding Added** - `Sapphire.padGas()` called in all `_update` hooks

### Medium Priority

5. **Consider Storage Obfuscation** (Future Enhancement)
   - Research ORAM implementations for access pattern obfuscation
   - Consider constant-size storage layouts
   - Note: This is a complex enhancement and may not be necessary for many use cases

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

**Status Update**: Significant progress has been made! Most critical privacy issues have been resolved.

### Summary of Current Privacy Status:

1.  **View Functions**: Access-controlled with `VIEWER_ROLE` - **FIXED**
2.  **Custom Events**: Encrypted using Sapphire precompiles - **FIXED**
3.  **Gas Padding**: Added to prevent side-channel leakage - **FIXED**
4.  **Standard Transfer Events**: Still emitted in plaintext - **REMAINING ISSUE**
5.  **Storage Access Patterns**: Still visible to compute nodes - **ACCEPTABLE LIMITATION**

### Remaining Privacy Leak:

**Standard Transfer Events**: The contracts still call `super._update()` which emits standard `Transfer` events from OpenZeppelin. These events expose:
- `from` address (sender)
- `to` address (receiver)
- `amount` or `tokenId` (transfer details)

**Impact**: Transfer history is publicly visible through standard events, even though encrypted events are also emitted.

**Solution**:
1. **Switch to Solmate/Solady** - Use library with public state variables (recommended)
2. **Copy Solmate files manually** - Full control, no external dependencies
3. **Accept tradeoff** - Keep OpenZeppelin but acknowledge privacy limitation (not recommended)

### Overall Assessment:

The implementation now provides:
-  **Confidential state** (encrypted storage)
-  **Access-controlled queryability** (view functions require authentication)
-  **Encrypted custom events** (additional privacy layer)
-  **Side-channel protection** (gas padding)
-  **Partial event privacy** (standard Transfer events still leak)

**Recommendation**: Address the standard Transfer event issue to achieve full privacy. The current implementation is significantly improved but still leaks transfer information through standard events.

