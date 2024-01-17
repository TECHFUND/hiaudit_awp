# Codehawks/Cyfrin -- TSwap (Modified for of UniswapV1) Security Review

## ToC

- [Codehawks/Cyfrin -- TSwap (Modified for of UniswapV1) Security Review](#codehawkscyfrin----tswap-modified-for-of-uniswapv1-security-review)
  - [ToC](#toc)
  - [Risk Classification](#risk-classification)
  - [Summary](#summary)
  - [High](#high)
    - [\[H-1\] `TSwapPool::deposit` is missing deadline check causing transaction to complete even after the deadline](#h-1-tswappooldeposit-is-missing-deadline-check-causing-transaction-to-complete-even-after-the-deadline)
    - [\[H-2\] Faulty calculation in `TSwapPool::getInputAmountBasedOnOutput` causes protocol to take too many tokens from users, resulting in lost fees](#h-2-faulty-calculation-in-tswappoolgetinputamountbasedonoutput-causes-protocol-to-take-too-many-tokens-from-users-resulting-in-lost-fees)
    - [\[H-3\] Missing slippage protection in `TSwapPool::swapExactOutput` causes users to potentially go through unexpected \& undesirable swaps](#h-3-missing-slippage-protection-in-tswappoolswapexactoutput-causes-users-to-potentially-go-through-unexpected--undesirable-swaps)
    - [\[H-4\] Misuse of `TSwapPool::swapExactOutput` within `TSwapPool::sellPoolTokens` leads to mismatched input and output tokens causing users to receive the incorrect amount of tokens](#h-4-misuse-of-tswappoolswapexactoutput-within-tswappoolsellpooltokens-leads-to-mismatched-input-and-output-tokens-causing-users-to-receive-the-incorrect-amount-of-tokens)
    - [\[H-5\] In `TSwapPool::_swap` the extra tokens given to users after every `swapCount` breaks the protocol invariant of `x * y = k`](#h-5-in-tswappool_swap-the-extra-tokens-given-to-users-after-every-swapcount-breaks-the-protocol-invariant-of-x--y--k)
  - [Medium](#medium)
    - [\[M-1\] Rebase, fee-on-transfer and ERC-777 tokens break protocol invariant](#m-1-rebase-fee-on-transfer-and-erc-777-tokens-break-protocol-invariant)
  - [Low](#low)
    - [\[L-1\] `TSwapPool::LiquidityAdded` event has parameters out of order](#l-1-tswappoolliquidityadded-event-has-parameters-out-of-order)
    - [\[L-2\] Default value returned by `TSwapPool::swapExactInput` results in incorrect return value given](#l-2-default-value-returned-by-tswappoolswapexactinput-results-in-incorrect-return-value-given)
  - [Gas](#gas)
    - [\[G-1\] Constants don't need to be emitted](#g-1-constants-dont-need-to-be-emitted)
    - [\[G-2\] `TSwapPool::deposit::poolTokenReserves` is never used, it should be removed](#g-2-tswappooldepositpooltokenreserves-is-never-used-it-should-be-removed)
  - [Informational](#informational)
    - [\[I-1\] Error `PoolFactory::PoolFactory__PoolDoesNotExist` is not used and should be removed](#i-1-error-poolfactorypoolfactory__pooldoesnotexist-is-not-used-and-should-be-removed)
    - [\[I-2\] Lacking zero address checks in `PoolFactory::constructor`](#i-2-lacking-zero-address-checks-in-poolfactoryconstructor)
    - [\[I-3\] `PoolFactory::createPool::liquidityTokenSymbol` should use `.symbol()` instead of `.name()`](#i-3-poolfactorycreatepoolliquiditytokensymbol-should-use-symbol-instead-of-name)
    - [\[I-4\] Events are missing `indexed` fields](#i-4-events-are-missing-indexed-fields)
    - [\[I-5\] Constants should be defined and used instead of literals](#i-5-constants-should-be-defined-and-used-instead-of-literals)
    - [\[I-6\] Make sure to follow CEI pattern in `TSwapPool::deposit`](#i-6-make-sure-to-follow-cei-pattern-in-tswappooldeposit)
    - [\[I-7\] Missing Natspec](#i-7-missing-natspec)
    - [\[I-8\] Functions not used internally could be marked external](#i-8-functions-not-used-internally-could-be-marked-external)


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
| High          | 5            |
| Medium        | 1            |
| Low           | 2            |
| Gas           | 2            |
| Informational | 8            |
| Total         | 18           |

## High

### [H-1] `TSwapPool::deposit` is missing deadline check causing transaction to complete even after the deadline

**Description:** The `deposit` function accepts a `deadline` parameter, which according to the natspec is:

> /// @param deadline The deadline for the transaction to be completed by

However, this parameter is never used. Consequently, operations that add liquidity to the pool might be executed at unexpected times, in market conditions where the deposit rate is unfavourable.

**Impact:** Transactions could be sent when the market conditions are unfavourable to deposit, even after adding a `deadline` parameter.

**Proof of Concept:**

```shell
# forge build
[⠢] Compiling...
[⠒] Compiling 7 files with 0.8.20
[⠑] Solc 0.8.20 finished in 3.30sCompiler run successful with warnings:
Warning (5667): Unused function parameter. Remove or comment out the variable name to silence this warning.
   --> src/TSwapPool.sol:122:9:
    |
122 |         uint64 deadline
    |
```

**Recommended Mitigation:**

```diff
function deposit(
    uint256 wethToDeposit,
    uint256 minimumLiquidityTokensToMint,
    uint256 maximumPoolTokensToDeposit,
    uint64 deadline
)
    external
+   revertIfDeadlinePassed(deadline)
    revertIfZero(wethToDeposit)
    returns (uint256 liquidityTokensToMint)
{
```

### [H-2] Faulty calculation in `TSwapPool::getInputAmountBasedOnOutput` causes protocol to take too many tokens from users, resulting in lost fees

**Description:** The `getInputAmountBasedOnOutput` function is intended to calculate the amount of tokens a user should deposit given an amount of tokens of output tokens. However, the function currently miscalculates the resulting amount. When calculating the fee, it scales the amount by 10_000 instead of 1_000.

**Impact:** Protocol takes more fees than expected from users.

**Recommended Mitigation:**

```diff
    function getInputAmountBasedOnOutput(
        uint256 outputAmount,
        uint256 inputReserves,
        uint256 outputReserves
    )
        public
        pure
        revertIfZero(outputAmount)
        revertIfZero(outputReserves)
        returns (uint256 inputAmount)
    {
-        return ((inputReserves * outputAmount) * 10_000) / ((outputReserves - outputAmount) * 997);
+        return ((inputReserves * outputAmount) * 1_000) / ((outputReserves - outputAmount) * 997);
    }
```

An even better solution would be to use constants in place of magic numbers.


### [H-3] Missing slippage protection in `TSwapPool::swapExactOutput` causes users to potentially go through unexpected & undesirable swaps

**Description:** The `swapExactOutput` function does not include any sort of slippage protection. This function is similar to what is done in `TSwapPool::swapExactInput`, where the function specifies a `minOutputAmount`, the `swapExactOutput` function should specify a `maxInputAmount`.

**Impact:** If market conditions change before the transaciton processes, the user could get a much worse swap.

**Proof of Concept:**
1. The price of 1 WETH right now is 1,000 USDC
2. User inputs a `swapExactOutput` looking for 1 WETH
   1. inputToken = USDC
   2. outputToken = WETH
   3. outputAmount = 1
   4. deadline = whatever
3. The function does not offer a maxInput amount
4. As the transaction is pending in the mempool, the market changes! And the price moves HUGE -> 1 WETH is now 10,000 USDC. 10x more than the user expected
5. The transaction completes, but the user sent the protocol 10,000 USDC instead of the expected 1,000 USDC

**Recommended Mitigation:** We should include a `maxInputAmount` so the user only has to spend up to a specific amount, and can predict how much they will spend on the protocol.

```diff
    function swapExactOutput(
        IERC20 inputToken,
+       uint256 maxInputAmount,
.
.
.
        inputAmount = getInputAmountBasedOnOutput(outputAmount, inputReserves, outputReserves);
+       if(inputAmount > maxInputAmount){
+           revert();
+       }
        _swap(inputToken, inputAmount, outputToken, outputAmount);
```

### [H-4] Misuse of `TSwapPool::swapExactOutput` within `TSwapPool::sellPoolTokens` leads to mismatched input and output tokens causing users to receive the incorrect amount of tokens

**Description:** The `sellPoolTokens` function is intended to allow users to easily sell pool tokens and receive WETH in exchange. Users indicate how many pool tokens they're willing to sell in the `poolTokenAmount` parameter. However, the function currently miscalculaes the swapped amount.

This is due to the fact that the `swapExactOutput` function is called, whereas the `swapExactInput` function is the one that should be called. Because users specify the exact amount of input tokens, not output.

**Impact:** Users will swap the wrong amount of tokens, which is a severe disruption of protcol functionality.

**Proof of Concept:**
1. The price of 1,000 USDC is 1 WETH right now.
2. User calls a `sellPoolTokens` with `poolTokenAmount` of `1000` looking for 1 WETH.
3. Input to `swapExactOutput` will be:
   1. inputToken: USDC
   2. outputToken: WETH
   3. outputAmount: 1000
   4. deadline: whatever

Even though the user's intention is to sell `1000 USDC` for `1 WETH` but, the call to function `swapExactOutput` from within `sellPoolTokens` is for selling enough USDC to output `1000 WETH`! In this example, this would be of the order `1_000_000 USDC`!

**Recommended Mitigation:**

Consider changing the implementation to use `swapExactInput` instead of `swapExactOutput`. Note that this would also require changing the `sellPoolTokens` function to accept a new parameter (ie `minWethToReceive` to be passed to `swapExactInput`)

```diff
    function sellPoolTokens(
        uint256 poolTokenAmount,
+       uint256 minWethToReceive,
        ) external returns (uint256 wethAmount) {
-        return swapExactOutput(i_poolToken, i_wethToken, poolTokenAmount, uint64(block.timestamp));
+        return swapExactInput(i_poolToken, poolTokenAmount, i_wethToken, minWethToReceive, uint64(block.timestamp));
    }
```

Additionally, it might be wise to add a deadline to the function, as there is currently no deadline.

### [H-5] In `TSwapPool::_swap` the extra tokens given to users after every `swapCount` breaks the protocol invariant of `x * y = k`

**Description:** The protocol follows a strict invariant of `x * y = k` for swapping between pool token & weth. Where:
- `x`: The balance of the pool token
- `y`: The balance of WETH
- `k`: The constant product of the two balances

This means, that whenever the balances change in the protocol due to a swap, the ratio between the two amounts should remain constant, hence the `k`. However, this is broken due to the extra incentive in the `_swap` function. Meaning that over time the protocol funds will be drained.

The follow block of code is responsible for the issue.

```javascript
        swap_count++;
        if (swap_count >= SWAP_COUNT_MAX) {
            swap_count = 0;
            outputToken.safeTransfer(msg.sender, 1_000_000_000_000_000_000);
        }
```

**Impact:** A user could maliciously drain the protocol of funds by doing a lot of swaps and collecting the extra incentive given out by the protocol.

Most simply put, the protocol's core invariant is broken.

**Proof of Concept:**
1. A user swaps 10 times, and collects the extra incentive of `1_000_000_000_000_000_000` tokens
2. That user continues to swap until all the protocol funds are drained

Place the following into `TSwapPoolTest` in `TSwapPool.t.sol`.

```javascript

function test_InvariantBroken() public {
    vm.startPrank(liquidityProvider);
    weth.approve(address(pool), 100e18);
    poolToken.approve(address(pool), 100e18);
    pool.deposit(100e18, 100e18, 100e18, uint64(block.timestamp));
    vm.stopPrank();

    uint256 numSwaps = 10;
    uint256 outputWeth = 1e17;
    uint256 startingY = weth.balanceOf(address(pool));
    int256 expectedDeltaY = int256(-1) *
        int256(outputWeth) *
        int256(numSwaps);

    vm.startPrank(user);
    poolToken.approve(address(pool), type(uint256).max);
    for (uint256 i = 0; i < numSwaps; ++i) {
        pool.swapExactOutput(
            poolToken,
            weth,
            outputWeth,
            uint64(block.timestamp)
        );
    }
    vm.stopPrank();

    uint256 endingY = weth.balanceOf(address(pool));
    int256 actualDeltaY = int256(endingY) - int256(startingY);

    assert(actualDeltaY == expectedDeltaY);
}
```

*Note*: Here for `TSwapPoolTest::test_InvariantBroken::numSwaps < 10` the test passes but, for values greater than or equal to `10` it fails. This value is determined by `TSwapPool::SWAP_COUNT_MAX`.


**Recommended Mitigation:** Remove the extra incentive mechanism. If you want to keep this in, we should account for the change in the x * y = k protocol invariant. Or, we should set aside tokens in the same way we do with fees.

```diff
-        swap_count++;
-        if (swap_count >= SWAP_COUNT_MAX) {
-            swap_count = 0;
-            outputToken.safeTransfer(msg.sender, 1_000_000_000_000_000_000);
-        }
```

## Medium

### [M-1] Rebase, fee-on-transfer and ERC-777 tokens break protocol invariant

**Description** Similar to [H-5] there are ERC20 compatible tokens (colloquially known as weird ERC20) which would perform unexpedcted transfers after a certain number of transfers are done. If a pool is created using such an ERC20 then, that pool will have it's invariant property broken.

**Proof of Concept**
- Examples of ERC20s that charge a fee: STA, PAXG
- Examples of ERC20s that do not charge a fee but, may do so in future: USDT, USDC

**Impact:** There are ERC20s which if used to create pools, will be used to drain out weth thereby breaking the protocol invariant and it's functionality.

**Recommended Mitigation:**
Read about:
- [Fee-on-transfer tokens](https://help.matcha.xyz/en/articles/7239773-what-are-fee-on-transfer-tokens)
- [Weird ERC20](https://github.com/d-xo/weird-erc20)

If possible, try to restrict which ERC20s can be used to create pools or modify the invariant to accomodate ERC20 fees like the 0.3% percent fee currently being taken from the user for each swap.


## Low

### [L-1] `TSwapPool::LiquidityAdded` event has parameters out of order

**Description:** When the `LiquidityAdded` event is emitted in the `TSwapPool::_addLiquidityMintAndTransfer` function, it logs values in an incorrect order. The `poolTokensToDeposit` value should go in the third parameter position, whereas the `wethToDeposit` value should go second.

**Impact:** Event emission is incorrect, leading to off-chain functions potentially malfunctioning.

**Recommended Mitigation:**

```diff
- emit LiquidityAdded(msg.sender, poolTokensToDeposit, wethToDeposit);
+ emit LiquidityAdded(msg.sender, wethToDeposit, poolTokensToDeposit);
```

### [L-2] Default value returned by `TSwapPool::swapExactInput` results in incorrect return value given

**Description:** The `swapExactInput` function is expected to return the actual amount of tokens bought by the caller. However, while it declares the named return value `ouput` it is never assigned a value, nor uses an explicit return statement.

**Impact:** The return value will always be 0, giving incorrect information to the caller.

**Recommended Mitigation:**

```diff
    {
        uint256 inputReserves = inputToken.balanceOf(address(this));
        uint256 outputReserves = outputToken.balanceOf(address(this));

-        uint256 outputAmount = getOutputAmountBasedOnInput(inputAmount, inputReserves, outputReserves);
+        output = getOutputAmountBasedOnInput(inputAmount, inputReserves, outputReserves);

-        if (outputAmount < minOutputAmount) {
-            revert TSwapPool__OutputTooLow(outputAmount, minOutputAmount);
+        if (output < minOutputAmount) {
+            revert TSwapPool__OutputTooLow(output, minOutputAmount);
        }

-        _swap(inputToken, inputAmount, outputToken, outputAmount);
+        _swap(inputToken, inputAmount, outputToken, output);
    }
```

## Gas

### [G-1] Constants don't need to be emitted

- Found in `src/TSwapPool.sol`

```solidity
if (wethToDeposit < MINIMUM_WETH_LIQUIDITY) {
    revert TSwapPool__WethDepositAmountTooLow(
@>      MINIMUM_WETH_LIQUIDITY,
        wethToDeposit
    );
}
```

### [G-2] `TSwapPool::deposit::poolTokenReserves` is never used, it should be removed

```diff
if (totalLiquidityTokenSupply() > 0) {
    uint256 wethReserves = i_wethToken.balanceOf(address(this));
-   uint256 poolTokenReserves = i_poolToken.balanceOf(address(this));
    // Our invariant says weth, poolTokens, and liquidity tokens must always have the same ratio after the
```

## Informational

### [I-1] Error `PoolFactory::PoolFactory__PoolDoesNotExist` is not used and should be removed

```diff
- error PoolFactory__PoolDoesNotExist(address tokenAddress);
```


### [I-2] Lacking zero address checks in `PoolFactory::constructor`

```diff
constructor(address wethToken) {
+   if (wethToken == address(0)) {
+       revert();
+   }
    i_wethToken = wethToken;
}
```

### [I-3] `PoolFactory::createPool::liquidityTokenSymbol` should use `.symbol()` instead of `.name()`

```diff
string memory liquidityTokenSymbol = string.concat(
    "ts",
-   IERC20(tokenAddress).name()
+   IERC20(tokenAddress).symbol()
);
```

### [I-4] Events are missing `indexed` fields

Index event fields make the field more quickly accessible to off-chain tools that parse events. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields). Each event should use three indexed fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three fields, all of the fields should be indexed.

- Found in src/PoolFactory.sol [Line: 35](src/PoolFactory.sol#L35)

	```solidity
	    event PoolCreated(address tokenAddress, address poolAddress);
	```

- Found in src/TSwapPool.sol [Line: 52](src/TSwapPool.sol#L52)

	```solidity
	    event LiquidityAdded(
            address indexed liquidityProvider,
            uint256 wethDeposited,
            uint256 poolTokensDeposited
        );
	```

- Found in src/TSwapPool.sol [Line: 57](src/TSwapPool.sol#L57)

	```solidity
	    event LiquidityRemoved(
            address indexed liquidityProvider,
            uint256 wethWithdrawn,
            uint256 poolTokensWithdrawn
        );
	```

- Found in src/TSwapPool.sol [Line: 62](src/TSwapPool.sol#L62)

	```solidity
	    event Swap(
            address indexed swapper,
            IERC20 tokenIn,
            uint256 amountTokenIn,
            IERC20 tokenOut,
            uint256 amountTokenOut
        );
	```

### [I-5] Constants should be defined and used instead of literals



- Found in src/TSwapPool.sol [Line: 275](src/TSwapPool.sol#L275)

	```solidity
        uint256 inputAmountMinusFee = inputAmount * 997;
	```

- Found in src/TSwapPool.sol [Line: 277](src/TSwapPool.sol#L277)

	```solidity
        uint256 denominator = (inputReserves * 1000) + inputAmountMinusFee;
	```

- Found in src/TSwapPool.sol [Line: 299](src/TSwapPool.sol#L299)

	```solidity
            ((inputReserves * outputAmount) * 10000) /
	```

- Found in src/TSwapPool.sol [Line: 300](src/TSwapPool.sol#L300)

	```solidity
            ((outputReserves - outputAmount) * 997);
	```

- Found in src/TSwapPool.sol [Line: 409](src/TSwapPool.sol#L409)

	```solidity
            outputToken.safeTransfer(msg.sender, 1_000_000_000_000_000_000);
	```

- Found in src/TSwapPool.sol [Line: 461](src/TSwapPool.sol#L461)

	```solidity
            1e18,
	```

- Found in src/TSwapPool.sol [Line: 470](src/TSwapPool.sol#L470)

	```solidity
            1e18,
	```

### [I-6] Make sure to follow CEI pattern in `TSwapPool::deposit`

`_addLiquidityMintAndTransfer` makes external calls and even though `liquidityTokensToMint` is not a storage variable, it is best to follow CEI.

```diff
} else {
    // This will be the "initial" funding of the protocol. We are starting from blank here!
    // We just have them send the tokens in, and we mint liquidity tokens based on the weth
+   liquidityTokensToMint = wethToDeposit;
    _addLiquidityMintAndTransfer(
        wethToDeposit,
        maximumPoolTokensToDeposit,
        wethToDeposit
    );
-   liquidityTokensToMint = wethToDeposit;
}
```

### [I-7] Missing Natspec

- `TSwapPool::swapExactInput` is a `public` function of significance. It should contain natspec documentation just like it's counterpart `TSwapPool::swapExactOutput` does.

- `TSwapPool::swapExactOutput` natspec is missing the `deadline` parameter.

### [I-8] Functions not used internally could be marked external

- Found in src/TSwapPool.sol [Line: 303](src/TSwapPool.sol#L303)

	```solidity
	    function swapExactInput(
	```