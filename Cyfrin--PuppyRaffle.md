### [M-#] Loop based duplicate-check in `PuppyRaffle::enterRaffle` vulnerable to Denial of Service (DoS) Attack, gas cost keeps incrementing for future participants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle starts will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make.

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. This will discourage later users from entering and cause a rush at the start of a raffle to be one of the first entrants in the queue.

An attacker might make `PuppyRaffle::players` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**

If we have *100 players* who each enter just themselves then the costs will be as such:

> - Gas cost for third player to enter    : 35627
> - Gas cost for last player to enter     : 3966957

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