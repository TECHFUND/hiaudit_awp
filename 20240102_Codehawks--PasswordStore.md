# Codehawks/Cyfrin -- Password Store Security Review

## ToC

- [Codehawks/Cyfrin -- Password Store Security Review](#codehawkscyfrin----password-store-security-review)
  - [ToC](#toc)
  - [Risk Classification](#risk-classification)
  - [Summary](#summary)
  - [High](#high)
    - [\[H-1\] Storing the password on-chain makes it visible to anyone, and no longer private](#h-1-storing-the-password-on-chain-makes-it-visible-to-anyone-and-no-longer-private)
    - [\[H-2\] `PasswordStore::setPassword` has no access controls, meaning a non-owner can change the password](#h-2-passwordstoresetpassword-has-no-access-controls-meaning-a-non-owner-can-change-the-password)
  - [Informational](#informational)
    - [\[I-1\] The `PasswordStore::getPassword` natspec indicates a parameter that doesn't exist](#i-1-the-passwordstoregetpassword-natspec-indicates-a-parameter-that-doesnt-exist)

## Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

## Summary

| Severity      | Issues Found |
| ------------- | ------------ |
| High          | 2            |
| Medium        | 0            |
| Low           | 0            |
| Gas           | 0            |
| Informational | 1            |
| Total         | 3            |


## High

### [H-1] Storing the password on-chain makes it visible to anyone, and no longer private

**Description:** All data stored on-chain is visible to anyone, and can be read directly from the blockchain. The `PasswordStore::s_password` variable is intended to be a private variable and only accessed through the `PasswordStore::getPassword` function, which is intended to be only called by the owner of the contract.

We show one such method of reading any data off chain below.

**Impact:** Anyone can read the private password, severely breaking the functionality of the protocol.

**Proof of Concept:** (Proof of Code)

The below test case shows how anyone can read from the blockchain.

1. Create a locally running chain

```bash
make anvil
```

2. Deploy the contract to the chain

```bash
make deploy
```

3. Run the storage tool

```bash
cast storage <ADDRESS_HERE> 1 --rpc-url http://127.0.0.1:8545
```

We use `1` because that's the storage slot of `s_password` in the contract.

You'll get an output that looks like this:

```bash
0x6d7950617373776f726400000000000000000000000000000000000000000014
```

You can then parse that hex to a string with:

```bash
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

And get an output of

```bash
myPassword
```

**Recommended Mitigation:** Due to this, the overall architecture of the contract should be rethought. One could encrypt the password off-chain and then store the encrypted password on-chain. This would require the user to remember another password off-chain to decrypt the password. However, you'd also likely want to remove the view function as you wouldn't want the user to accidentally send a transaction with the password that decrypts your password.

### [H-2] `PasswordStore::setPassword` has no access controls, meaning a non-owner can change the password

**Description:** The `Password::setPassword` function is set to be an `external` function. The natspec of the function and overall purpose of the smart contract is that `This function allows only the owner to set a new password.`

```javascript
    function setPassword(string memory newPassword) external {
@>      // @audit any user can set a password.
        s_password = newPassword;
        emit SetNetPassword();
    }
```

**Impact:** Anyone can set/change the password of the contract, severely breaking the contract's intended functionality.

**Proof of Concept:** Add the following to the `PasswordStore.t.sol` test file:

<details>
<summary>Code</summary>

```javascript
    function test_anyone_can_set_password(address randomAddress) public {
        vm.assume(randomAddress != owner);
        vm.prank(randomAddress);
        string memory expectedPassword = "myNewPassword";
        passwordStore.setPassword(expectedPassword);

        vm.prank(owner);
        string memory actualPassword = passwordStore.getPassword();
        assertEq(actualPassword, expectedPassword);
    }
```

</details>

**Recommended Mitigation:** Add an access control conditional to the `setPassword` function.

```javascript
    if(msg.sender != s_owner) {
        revert PasswordStore__NotOwner();
    }
```

## Informational

### [I-1] The `PasswordStore::getPassword` natspec indicates a parameter that doesn't exist

**Description:**

```javascript
    /*
     * @notice This allows only the owner to retrieve the password.
@>   * @param newPassword The new password to set.
     */
    function getPassword() external view returns (string memory) {
```

The `Password::getPassword` function signature is `getPassword()` while the natspec says it should be `getPassword(string)`.

**Impact:** The natspec is incorrect.

**Recommended Mitigation:** Remove the incorrect natspec line.

```diff
-   * @param newPassword The new password to set.
```
