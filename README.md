# zkpython
A zero-knowledge succinct non-interactive argument of knowledge (zk-SNARK) implementation in Python.

## Getting Started

1. Clone the Repository
2. Copy the `ZeroKnowlege` Directory to your Project Directory
3. Use the following code to import the package in your project
    ```
    from ZeroKnowledge.Zk import Zk
    ```
4. Initialize a Zk Object
    ```
    zero = Zk()
    ```
You're ready to go.

## Usage

Functions | Definition | Params | Returns
--- | --- | --- | ---
`changeSecret()` | Allows you to add your custom secret| secret = An array of secret numbers | secret
`getSecret()` | Lets you view the current secret | None | secret
`create()` | Lets you create a ZK-proof of a String | data = A string of data | Commitments of the proof
`solve()` | Lets you solve a ZK-proof to get the original data | secret, commitments | Solved String Data
