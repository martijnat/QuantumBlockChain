# Quantum block chain

A Program to show how simple a blockchain really is.

The rise of bitcoin has gotten people to treat the blockchain
technology as if it were some black magic that can be applied to
everything. In reality it is a very simple idea that is only well
suited for very sepecific use cases. For most use cases there are more
effecient methods.

# Inner workings

This blockchain consists of 64-byte blocks structured as followed.

    32-byte Data || 32-byte random data

a block-hash is calculated as follows

     sha256(previous-block-hash || 32-byte Data || 32-byte random data)

the previous-block-hash for the first block is all zero-bytes

A block is considered valid is the block-hash sadis "hard" enough. For
this program I have define the hardness as the hash requiring to have
the final n/32 bits be zero for the n-th block.

Mining a block is just creating a new 64 byte block with a given
prefix and trying random prefix until the block hash satisfies the
hardness requirement.

That's it.

# Example

As an example the program builds a blockchain from stdin

For example

    man man | ./qbc.py

mines a blockchain based of the contents of the man manpage

