### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain all the reffle balance 


**Description:** `PuppyRaffle::refund` don't follow the `CEI` rule 

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

@>        payable(msg.sender).sendValue(entranceFee);
@>        players[playerIndex] = address(0);
        emit RaffleRefunded(playerAddress);
    }
```

A player who entered the `PuppyRaffle::refund` raffle could have the `fallback`/`recevie` function and able to get the balance of the raffle till the balance reaches to zero.

**Impact:** All fees paid by participants could be stolen by malicious participants.

**Proof of Concept:** 

User entered the `PuppyRaffle` and the attacker comes in the the contract having the fallback and receive fuction in there contract and the call the attack function and call the the `PuppyRaffle::refund` function and drain all the money from that contract.


**Proof of Code:**

<details>
<summary>Code</summary>

Place this code in the `PuppyRaffleTest.t.sol` file

```javascript
 function testReenterancyAttrack() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);

        attacker attackerContract = new attacker(puppyRaffle);
        address userAttacker = makeAddr("userAttacker");
        vm.deal(userAttacker, 1 ether);

        uint256 startingAttackerContractBalance = address(attackerContract)
            .balance;
        uint256 startingContractBalance = address(puppyRaffle).balance;

        vm.prank(userAttacker);
        attackerContract.attack{value: entranceFee}();

        console.log(
            "starting attackerContract balance",
            startingAttackerContractBalance
        );
        console.log("starting contract balance", startingContractBalance);

        console.log(
            "ending attacketContract balance",
            address(attackerContract).balance
        );
        console.log("ending contrac balance", address(puppyRaffle).balance);
    }
```
</details>

**Recommended Mitigation:** To prevent this we should update the `PuppyRaffle::refunds` by updating the `players` array before calling the extarnal call. We should follow the `CEI` rule over there. 


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
+     players[playerIndex] = address(0);
+      emit RaffleRefunded(playerAddress);

        payable(msg.sender).sendValue(entranceFee);

-       players[playerIndex] = address(0);
-     emit RaffleRefunded(playerAddress);

    }
```
### [H-2] Week randomness in `PuppyRaffle::selectWinner` allow users and minner to predict the winner.

**Description:** Hashing the `msg.sender` `block.timestamp` and `block.difficulty` make the predictable winner and controlled by the minner to choose the winner. 

**Impact:** Minners and influence the winner for the raffle. and also select the `rarest` puppy.

**Proof of Concept:** 

Validator are ahead to time by meanipulating the `block.timestamp` and `block.difficulty` and use to predict the when/how to participate see the  [solidity blog on prevrandso](https://soliditydeveloper.com/prevrandao). `block.difficulty` is recently update with `prevrandao`.

**Recommended Mitigation:** Use the chainlink VRF to genrate the randomness. 

### [H-3] Integer overflow of `PupplyRaffle::totalFee` loos fee

**Description:** In solidity version prior to `0.8.0` the integer are subject to overflow.

```javascript

uint64 myvar = type(64).max;
// => 18446744073709551615

myvar = myvar + 1 ;
// => 0 
```

**Impact:** In the `PupplyRaffle::selectWinner` `totalFee` is accumulated in `feeaddress` to collect later in the withdraw fee however if the `totalFee` variable is overflow then the `feeaddress` may not able to collect the correct amount of fee. leaving fee parmanently stuck in contract. 

**Proof of Concept:** 

<details>
<summary>Code</summary>

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

**Recommended Mitigation:** 
1. Use the newer version of solidity and use the `uint256` instead of `uint64` in order to collect fee 
2. If you want to use the older version of solidity then you need to use the `safemath` function form openzeplllin library.
3. Remove the balance check from the `puppyRaffle::withdrawFees` 

```diff
-  require(   address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

this could be harmed by the `selfdestruct` function and then this require statament is gone wrong. 




# Medium

### [M-1] Looping trough the `players` array for the duplicates checks in the `PuppyRaffle::enterRaffle` is a potential Denial of service (DoS) , incrementing gas cost for the future enterences. 

**Description:** The `PuppyRaffle::enterRaffle` function currently checks for duplicate entries by iterating over the `players[]` array, which leads to an O(n²) time complexity as the number of participants grows. This method increases gas costs with each new entry and makes the contract vulnerable to Denial of Service (DoS) attacks by making transactions increasingly expensive over time. To optimize this, using a `mapping(address => bool)` for duplicate checks would provide constant time (O(1)) efficiency. This approach stores each player's address as a key and checks for duplicates in constant time, preventing gas cost escalation, enhancing scalability, and improving overall contract usability.

```javascript
   // Check for duplicates
        for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(
                    players[i] != players[j],
                    "PuppyRaffle: Duplicate player"
                );
            }
        }
```

**Impact:** The `PuppyRaffle::enterRaffle` itrates through the `players[]` array which make more gas cost for the later users. The users that are comming into raffle first get the advantage over the other players how are entering latter in the raffle.

One more thing that the attacker can make the `PuppyRaffle::enterRaffle` array so big that the gas cost sky rokets and no any new users are able to get in the raffes and attacker try to make themselves winner.

**Proof of concept:** 

if we have a two sets of entered players into raffle. Then the gas costs will be as such:

- 1st 100 players: ~6252128
- 2nd 100 players: ~18068218

3 times more expensive for the second 100 players.

<details>
<summary>PoC</summary>
Place the following test into the `PuppyRaffle.t.sol` file:

```javascript
 function testDenialOfServices() public {
        vm.txGasPrice(1);

        // let's entered 100 players

        uint256 playerNum = 100;
        address[] memory playars = new address[](playerNum);
        for (uint256 i = 0; i < playerNum; i++) {
            playars[i] = address(i);
        }

        //how much gas does it cost

        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playars.length}(playars);
        uint256 endGas = gasleft();

        uint256 gasUsedFirst = (gasStart - endGas) * tx.gasprice;
        console.log(
            "gas cost at the entery of first 100 players: ",
            gasUsedFirst
        );

        // for second 100 players
        address[] memory playars2 = new address[](playerNum);
        for (uint256 i = 0; i < playerNum; i++) {
            playars2[i] = address(i + playerNum);
        }

        //how much gas does it cost

        uint256 gasStart2 = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playars2.length}(playars2);
        uint256 endGas2 = gasleft();

        uint256 gasUsedSecond = (gasStart2 - endGas2) * tx.gasprice;
        console.log(
            "gas cost at the entery of second 100 players: ",
            gasUsedSecond
        );

        assert(gasUsedFirst < gasUsedSecond);
    }
```
</details>

**Recommended Mitigation:**  
To optimize your `enterRaffle` function by eliminating the duplicate checks with a mapping, you'll want to:

1. **Remove the nested loop for duplicate checks.**
2. **Introduce a mapping to track active players.**
3. **Add logic to update the mapping and emit the event only for new entries.**

Here's a cleaned-up version of your `enterRaffle` function with the suggested changes:

```solidity
function enterRaffle(address[] memory newPlayers) public payable {
    require(
        msg.value == entranceFee * newPlayers.length,
        "PuppyRaffle: Must send enough to enter raffle"
    );

    for (uint256 i = 0; i < newPlayers.length; i++) {
        require(!activePlayers[newPlayers[i]], "PuppyRaffle: Duplicate player");
        players.push(newPlayers[i]);
        activePlayers[newPlayers[i]] = true; // Add to mapping
    }

    emit RaffleEnter(newPlayers);
}
```

# Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` return the zero index for non-existing players but if the user entered first and they have the zeroth index and user may think that they might we in active players. 

**Description:** If the player in `PuppyRaffle::getActivePlayerIndex` is at index 0 , then it will return the zero index , but according to netspec if there is no active player in `PuppyRaffle::getActivePlayerIndex` it will also return the zero index.

**Impact:** A player at Index 0 is incorrectly think that he is still not entered the raffle and try to do this again , which is nothing but the waste of gass fee. 

**Recommended Mitigation:** If the player in the `PuppyRaffle::getActivePlayerIndex` is not exist then the better option might be return the revert or also use the int256 to return the -1 instead. 


# Gas 

### [G-1] Unchanged state variables should be declared as constants or immutable

**Discription** Reading from storage is much more expensive than reading from immutable storage and constants.

- Instances:
- `puppyRaffle::raffleDuration` should be `immutable`
- `puppyRaffle::commonImgUri` should be `constand`
- `puppyRaffle::rareImageUri` should be `constant`
- `puppyRaffle::legendryImageUri` should be `constant`


### [G-2] Storage variables in a loop should be cahced 

**Discription** Eveytime we read from `player.length` in loop it reads from the storage which should be more gass costly then the memory so modify the lood as follows:

```diff
+   uin256 players = players.length
-  for (uint256 i = 0; i < players.length - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
-               require(
-                   players[i] != players[j],
-                   "PuppyRaffle: Duplicate player"
-               );
-           }
-       }

```


### [I-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`


<details><summary>1 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```

</details>

# Informational 

### [I-2] Using a outdated version of solidity is not recommended

**Description:**
solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation:**
Deploy with a recent version of Solidity (at least `0.8.0`) with no known severe issues.

Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

follow the [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information


### [I-3] Missing checks for `address(0)` when assigning values to address state variables

Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 70](src/PuppyRaffle.sol#L70)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 212](src/PuppyRaffle.sol#L212)

	```solidity
	        feeAddress = newFeeAddress;
	```

</details>

### [I-4] `PuppyRaffle::selectWinner` does not follow the `CEI` which is not a best practice 

### [I-5] Use of magic numbers is discouraged 

### [I-6] State change missing events , every time when state changes there must be an event emitted 

### [I-7] `PuppyRaffle::_isActivePlayer` is never used , so it's safe to remove it 



