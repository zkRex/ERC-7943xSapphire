# uRWA20 Test Status

**Test Run Date:** November 22, 2025  
**Test File:** `test/uRWA20.ts`  
**Network:** sapphire-localnet  
**Test Duration:** ~8 minutes  
**Log File:** `test-results-urwa20-20251122-220827.log`

## Summary

- **Total Tests:** 19
- **Passing:** 5
- **Failing:** 13
- **Pending:** 1
- **Success Rate:** 26.3%

## Test Results by Category

### Deployment Tests

| Test | Status | Notes |
|------|--------|-------|
| Should deploy successfully | PASS | Contract deploys correctly |
| Should have correct name and symbol | PASS | Name and symbol are set correctly |
| Should grant all roles to initialAdmin | PASS | Initial admin receives all roles (117ms) |

### Interface Support Tests

| Test | Status | Notes |
|------|--------|-------|
| Should support IERC7943Fungible interface | PASS | Interface detection works correctly |

### canTransact Tests

| Test | Status | Error |
|------|--------|-------|
| Should return false for non-whitelisted account | FAIL | `ContractFunctionExecutionError: The contract function "canTransact" reverted` |
| Should return true for whitelisted account | FAIL | `ContractFunctionExecutionError: The contract function "canTransact" reverted` |
| Should return false after removing from whitelist | FAIL | `ContractFunctionExecutionError: The contract function "canTransact" reverted` |

**Issue:** The `canTransact` view function is reverting on all calls. This suggests a potential access control issue or missing VIEWER_ROLE check in the contract implementation.

### changeWhitelist Tests

| Test | Status | Error |
|------|--------|-------|
| Should allow WHITELIST_ROLE to change whitelist status | FAIL | `ContractFunctionExecutionError: The contract function "canTransact" reverted` (called during verification) |
| Should revert when called by non-whitelist role | PASS | Access control works correctly (1158ms) |

**Issue:** The test fails because it calls `canTransact` to verify whitelist status, which is reverting.

### mint Tests

| Test | Status | Error |
|------|--------|-------|
| Should allow MINTER_ROLE to mint tokens | FAIL | `ContractFunctionExecutionError: The contract function "balanceOf" reverted` |
| Should revert when minting to non-whitelisted account | FAIL | `ContractFunctionExecutionError: The contract function "canTransact" reverted` |
| Should revert when called by non-minter role | PENDING | Test skipped |

**Issue:** 
- `balanceOf` view function is reverting, preventing balance verification after minting
- `canTransact` revert prevents checking whitelist status before minting

### burn Tests

| Test | Status | Error |
|------|--------|-------|
| Should allow BURNER_ROLE to burn tokens | FAIL | `ContractFunctionExecutionError: The contract function "balanceOf" reverted` |
| Should revert when called by non-burner role | FAIL | `AssertionError: expected promise to be rejected but it was fulfilled` - Transaction succeeded when it should have reverted |

**Issue:**
- `balanceOf` revert prevents balance verification after burning
- Access control for burn function may not be properly enforced

### setFrozenTokens Tests

| Test | Status | Error |
|------|--------|-------|
| Should allow FREEZING_ROLE to freeze tokens | FAIL | `ContractFunctionExecutionError: The contract function "getFrozenTokens" reverted` |
| Should revert when called by non-freezing role | FAIL | `AssertionError: expected promise to be rejected but it was fulfilled` - Transaction succeeded when it should have reverted |

**Issue:**
- `getFrozenTokens` view function is reverting
- Access control for freezing function may not be properly enforced

### transfer restrictions Tests

| Test | Status | Error |
|------|--------|-------|
| Should allow transfer between whitelisted accounts | FAIL | `Error: Timeout of 120000ms exceeded` - Test timed out |
| Should revert transfer from non-whitelisted account | FAIL | `AssertionError: expected promise to be rejected but it was fulfilled` - Transfer succeeded when it should have reverted |
| "before each" hook for "Should revert transfer to non-whitelisted account" | FAIL | `Error: Timeout of 120000ms exceeded` - Setup hook timed out |

**Issue:**
- Transfer restrictions may not be properly enforced
- Tests are timing out, suggesting potential deadlocks or infinite loops

## Critical Issues

### 1. View Function Reverts

Multiple view functions are reverting, which suggests access control issues:

- **`canTransact(address)`** - Reverting on all calls
- **`balanceOf(address)`** - Reverting on all calls  
- **`getFrozenTokens(address)`** - Reverting on all calls

**Root Cause Hypothesis:** These view functions likely require VIEWER_ROLE, but the test accounts may not have proper access or the contract's access control logic may be incorrect.

### 2. Access Control Enforcement

Several functions that should revert for unauthorized users are succeeding:

- `burn` - Non-burner role can burn tokens
- `setFrozenTokens` - Non-freezing role can freeze tokens
- `transfer` - Non-whitelisted accounts can transfer

**Root Cause Hypothesis:** Access control modifiers may not be properly applied or role checks may be missing.

### 3. Test Timeouts

Transfer tests are timing out, suggesting:

- Potential deadlocks in contract logic
- Network connectivity issues
- Infinite loops in contract execution

## Recommendations

1. **Investigate View Function Access Control**
   - Verify VIEWER_ROLE is properly granted in test setup
   - Check if view functions require VIEWER_ROLE and if the check is implemented correctly
   - Review contract implementation for `canTransact`, `balanceOf`, and `getFrozenTokens`

2. **Review Access Control Modifiers**
   - Verify all state-changing functions have proper access control modifiers
   - Check role-based access control (RBAC) implementation
   - Ensure `burn`, `setFrozenTokens`, and `transfer` functions enforce proper restrictions

3. **Debug Transfer Logic**
   - Investigate why transfer tests are timing out
   - Check for potential infinite loops or deadlocks
   - Review whitelist checking logic in transfer functions

4. **Test Infrastructure**
   - Verify Sapphire localnet is running correctly
   - Check if signed queries are properly configured for view functions
   - Review the `readToken` helper function implementation

## Next Steps

1. Review contract implementation (`contracts/uRWA20.sol`) for access control issues
2. Verify test setup and role granting logic
3. Check Sapphire-specific requirements for view function calls
4. Fix access control enforcement in state-changing functions
5. Re-run tests after fixes

## Test Environment

- **Hardhat Version:** ^2.27.0
- **Viem Version:** ^2.39.3
- **Network:** sapphire-localnet
- **Test Framework:** Mocha with Chai
- **Timeout:** 120000ms (2 minutes)

