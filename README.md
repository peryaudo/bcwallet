# bcwallet.rb: A stand-alone Bitcoin client within approx. 800 LOC!

bcwallet.rb is an educational Bitcoin client written in Ruby language.

The client is written for [Bitcoin no shikumi](http://bitcoin.peryaudo.org/) ("The Mechanism of Bitcoin"), a Japanese website describes Bitcoin from the technical perspective.

## Features

* Stand-alone Bitcoin client within approx. 800 lines of code (counted by CLOC)
  * Generate address, export key, show balances for addresses, send coins from addresses ...
* Written in pure Ruby
  * No additional dependencies
* Implements Simplified Payment Verification (SPV)
* Comments to help you understand how Bitcoin client is implemented
* Testnet supported (use in main network is not recommended)

## Usage

    Usage: ruby bcwallet.rb <command> [<args>]
    commands:
        generate <name>             generate a new Bitcoin address
        list                        show list for all Bitcoin addresses
        export <name>               show private key for the Bitcoin address
        balance                     show balances for all Bitcoin addresses
        send <name> <to> <amount>   transfer coins to the Bitcoin address

## Dependencies

* Ruby >= 2.0.0

## Disclaimer

DO NOT USE THIS CLIENT IN MAIN NETWORK, OR YOU MAY LOSE YOUR COINS!

Because this client is for technical education, it skips a lot of validations and may have critical bugs.

Use [Testnet](https://en.bitcoin.it/wiki/Testnet) instead. Testnet coins are worthless coins. You can receive Testnet coins for free at [TP's TestNet Faucet](http://tpfaucet.appspot.com/) to try this client.

## License

The MIT License (MIT)

Copyright (c) 2014 peryaudo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## ToDo

* Write Merkle tree validation for transactions
