<!-- b1f5ef18-d6e7-49f8-9324-15595ce9eb17 3a82b66d-d13f-4f72-8922-d294041ac9ba -->
# Update Test Cases for VIEWER_ROLE Access Control

## Problem

The contracts now require `VIEWER_ROLE` for all view functions (`balanceOf`, `canTransact`, `canTransfer`, `getFrozenTokens`, `ownerOf`, etc.), but the tests don't grant this role to test accounts. This will cause all view function calls to fail with "Access denied".

## Solution

Update all three test files (`uRWA20.ts`, `uRWA721.ts`, `uRWA1155.ts`) to:

1. Grant `VIEWER_ROLE` to test accounts in the setup
2. Ensure all view function calls are made by accounts with `VIEWER_ROLE`
3. Add tests to verify unauthorized view calls are rejected

## Implementation Details

### 1. Update Test Setup (All Files)

- Grant `VIEWER_ROLE` to `owner`, `otherAccount`, and `thirdAccount` in the `deployTokenFixture` function
- The owner already has `VIEWER_ROLE` from constructor, but we should explicitly grant it to other accounts
- Use `token.write.grantRole([VIEWER_ROLE, accountAddress])` after deployment

### 2. Update Existing Tests

- All tests that call view functions should work after granting roles
- No changes needed to test logic, just ensure roles are granted before view calls

### 3. Add New Tests for Access Control

- Add test suite "View function access control" to each test file
- Test that unauthorized accounts cannot call view functions
- Test that accounts with `VIEWER_ROLE` can call view functions

### 4. Helper Function (Optional)

- Consider adding a helper function in `utils.ts` to grant `VIEWER_ROLE` to multiple accounts at once

## Files to Modify

1. **test/uRWA20.ts**

   - Grant `VIEWER_ROLE` in `deployTokenFixture` to all test accounts
   - Add access control test suite

2. **test/uRWA721.ts**

   - Grant `VIEWER_ROLE` in `deployTokenFixture` to all test accounts
   - Add access control test suite

3. **test/uRWA1155.ts**

   - Grant `VIEWER_ROLE` in `deployTokenFixture` to all test accounts
   - Add access control test suite

4. **test/utils.ts** (Optional)

   - Add helper function `grantViewerRole(token, accounts, publicClient)` if needed

## Test Structure Example

```typescript
describe("View function access control", function () {
  it("Should allow VIEWER_ROLE to call balanceOf", async function () {
    // Test that accounts with VIEWER_ROLE can call view functions
  });
  
  it("Should revert view calls from unauthorized accounts", async function () {
    // Create a new account without VIEWER_ROLE
    // Verify view calls revert
  });
});
```

## Notes

- The owner account already has `VIEWER_ROLE` from the constructor, but granting it explicitly doesn't hurt
- On Sapphire, unsigned view calls have `msg.sender == address(0)`, which will fail the access check
- All existing tests should continue to work once roles are granted properly

### To-dos

- [ ] Update uRWA20.ts to grant VIEWER_ROLE to all test accounts in deployTokenFixture and add access control tests
- [ ] Update uRWA721.ts to grant VIEWER_ROLE to all test accounts in deployTokenFixture and add access control tests
- [ ] Update uRWA1155.ts to grant VIEWER_ROLE to all test accounts in deployTokenFixture and add access control tests
- [ ] Optionally add helper function in utils.ts to grant VIEWER_ROLE to multiple accounts