# Security Fixes for uRWA20 Privacy

## Summary

Fixed multiple privacy leakage vulnerabilities in the uRWA20 contract by copying and modifying Solady's ERC20 base contract to suppress standard events and adding encrypted event emissions.

## Issues Fixed

### 1. Standard ERC20 View Functions Leaked Data
**Functions affected:**
- `balanceOf(address account)`
- `totalSupply()`
- `allowance(address owner, address spender)`
- `nonces(address owner)`

**Problem:** These functions were callable without authentication, allowing anyone to read sensitive balance and allowance data.

**Fix:** 
- Overridden to return `0` for unauthenticated view calls (`msg.sender == address(0)`)
- Require `VIEWER_ROLE` for transaction calls
- Added authenticated versions with SIWE token parameter:
  - `balanceOf(address account, bytes memory token)`
  - `totalSupply(bytes memory token)`
  - `allowance(address owner, address spender, bytes memory token)`

### 2. Standard Transfer/Approval Events Leaked Data
**Events affected:**
- `Transfer(address indexed from, address indexed to, uint256 amount)`
- `Approval(address indexed owner, address indexed spender, uint256 amount)`

**Problem:** These events were emitted by the base Solady ERC20, revealing transaction details publicly.

**Fix:**
- Created local copy of Solady ERC20 at `contracts/base/ERC20.sol`
- Commented out all `log3` event emissions in the base contract
- Added encrypted event emissions in uRWA20:
  - `EncryptedTransfer(bytes encryptedData)` - for transfers
  - `EncryptedApproval(bytes encryptedData)` - for approvals

### 3. Approve/Permit Functions Didn't Check Whitelists
**Functions affected:**
- `approve(address spender, uint256 amount)`
- `permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)`

**Problem:** Could approve non-whitelisted addresses, bypassing RWA compliance.

**Fix:**
- Overridden both functions to check whitelist status
- Added whitelist requirement: both owner and spender must be whitelisted
- Emit `EncryptedApproval` events instead of standard `Approval` events

## Implementation Details

### Modified Base Contract
- **File:** `contracts/base/ERC20.sol`
- **Source:** Copied from `solady@0.1.26/src/tokens/ERC20.sol`
- **Modifications:** All `log3` calls commented out (9 locations total)
  - Lines for `Transfer` events in: `transfer()`, `transferFrom()`, `_mint()`, `_burn()`, `_transfer()`
  - Lines for `Approval` events in: `approve()`, `permit()`, `_approve()`

### uRWA20 Changes
1. **Import:** Changed from `solady/src/tokens/ERC20.sol` to `./base/ERC20.sol`
2. **New Event:** Added `EncryptedApproval(bytes encryptedData)`
3. **Overridden Functions:**
   - `balanceOf(address)` - Returns 0 for view calls
   - `totalSupply()` - Returns 0 for view calls
   - `allowance(address, address)` - Returns 0 for view calls
   - `nonces(address)` - Returns 0 for view calls
   - `approve(address, uint256)` - Checks whitelists, emits encrypted event
   - `permit(...)` - Checks whitelists, emits encrypted event

## Usage

### For Frontend/Users
Use the authenticated versions with SIWE tokens:
```solidity
// Get balance with authentication
uint256 balance = token.balanceOf(address, siweToken);

// Get total supply with authentication
uint256 supply = token.totalSupply(siweToken);

// Get allowance with authentication
uint256 allowed = token.allowance(owner, spender, siweToken);
```

### Standard ERC20 Functions
Standard functions still work but return 0 for unauthenticated view calls:
```solidity
// Returns 0 for view calls without VIEWER_ROLE
uint256 balance = token.balanceOf(address);
```

### For Contracts/Transactions
Functions work normally when called from contracts (msg.sender != address(0)) if caller has `VIEWER_ROLE`.

## Encrypted Event Format

All sensitive events are encrypted using Sapphire's encryption:
```solidity
bytes memory plaintext = abi.encode(
    from,
    to,
    amount,
    action,  // "transfer", "approve", "permit", etc.
    block.timestamp,
    nonce
);
bytes memory encrypted = Sapphire.encrypt(
    _encryptionKey,
    nonce,
    plaintext,
    abi.encode(address(this))
);
```

Only authorized parties can decrypt:
- Transaction participants (sender/receiver)
- Addresses with `VIEWER_ROLE`
- Addresses with auditor permissions

## Security Benefits

1. **Privacy:** Balance and allowance data not publicly visible
2. **Compliance:** Whitelists enforced on all approvals
3. **Auditability:** Encrypted events can be decrypted by authorized parties
4. **ERC20 Compatible:** Standard interface maintained (returns 0 for unauthorized access)

## Testing Required

After deployment, verify:
1. Unauthenticated `balanceOf()` calls return 0
2. Authenticated `balanceOf(address, bytes)` calls work correctly
3. No `Transfer` or `Approval` events in transaction logs
4. `EncryptedTransfer` and `EncryptedApproval` events are emitted
5. Encrypted events can be decrypted by authorized parties
6. `approve()` and `permit()` reject non-whitelisted addresses


