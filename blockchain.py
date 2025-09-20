"""
Minimal Proof-of-Work (PoW) blockchain with a Flask API.

Features
--------
- Block structure with index, timestamp, transactions, nonce, and previous-hash pointer
- Simple PoW consensus using a fixed difficulty prefix (e.g., "0000")
- Transaction pool that is flushed into a new block upon mining
- Peer discovery and a very simple longest-valid-chain conflict resolution
- JSON REST endpoints for inspecting the chain, mining, posting transactions,
  adding peers, and syncing with neighbors

Run
---
$ python blockchain.py 5000
Then open: http://localhost:5000/blockchain

API Endpoints
-------------
GET  /blockchain         -> Return full chain (JSON)
GET  /mine               -> Mine a block; reward is added to the miner's address
POST /transactions/new   -> Add a new transaction {"sender","recipient","amount"}
POST /nodes/add_nodes    -> Register peer nodes {"nodes": ["host:port", ...]}
GET  /nodes/sync         -> Sync with peers; adopt the longest valid chain
GET  /nodes              -> List known peer nodes
"""

import sys
import hashlib
import json

from time import time
from uuid import uuid4

from flask import Flask
from flask.globals import request
from flask.json import jsonify

import requests
from urllib.parse import urlparse


class Blockchain(object):
    """
    A very small blockchain implementation with:
    - an in-memory chain
    - a list (pool) of current (unconfirmed) transactions
    - a simple Proof-of-Work (PoW) algorithm
    - naïve peer management and longest-chain conflict resolution
    """

    # Difficulty target for PoW: the SHA-256 hash must start with this prefix.
    # In practice, the longer the prefix of leading zeros, the more difficult
    # (and slower) mining becomes. Example: "0000" ≈ 1 in 16^4 = 1/65536 chance.
    difficulty_target = "0000"

    def __init__(self):
        """
        Initialize the blockchain:
        - nodes: a set of known peer addresses (host:port)
        - chain: the list of confirmed blocks
        - current_transactions: the mempool of unconfirmed txns
        - genesis block: the first block, pointing to a "genesis" previous hash
        """
        # Known peers (unique host:port strings)
        self.nodes = set()

        # The confirmed blockchain (list of block dicts)
        self.chain = []

        # Unconfirmed transactions waiting to be included in the next block
        self.current_transactions = []

        # Create the "genesis" block by referencing a fixed prior-hash surrogate
        genesis_hash = self.hash_block("genesis_block")

        # Append the genesis block (index 0) with a valid PoW nonce
        self.append_block(
            hash_of_previous_block=genesis_hash,
            nonce=self.proof_of_work(0, genesis_hash, []),
        )

    # -----------------------------
    # Core crypto / chain utilities
    # -----------------------------

    def hash_block(self, block):
        """
        Deterministically hash a block (or any JSON-serializable object).
        The object is canonicalized with sort_keys=True to ensure stable hashes.

        Parameters
        ----------
        block : Any
            The block (or data) to hash.

        Returns
        -------
        str
            The SHA-256 hexadecimal digest.
        """
        block_encoded = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_encoded).hexdigest()

    # -----------------------------
    # Peer management / consensus
    # -----------------------------

    def add_node(self, address):
        """
        Register a new peer node.

        Parameters
        ----------
        address : str
            A URL-like address, e.g. "http://127.0.0.1:5001" or "http://host:port".

        Notes
        -----
        We keep only the 'netloc' (host:port) so we can build "http://{node}/..." later.
        """
        parse_url = urlparse(address)
        self.nodes.add(parse_url.netloc)
        print(f"[peer] added: {parse_url.netloc}")

    def valid_chain(self, chain):
        """
        Validate a candidate chain:
        - Each block must properly reference the previous block's hash.
        - Each block's PoW must satisfy the difficulty target.

        Parameters
        ----------
        chain : list[dict]
            The candidate blockchain to validate.

        Returns
        -------
        bool
            True if valid; False otherwise.
        """
        if not chain:
            return False

        last_block = chain[0]
        current_index = 1

        # Walk forward and validate linkage and PoW at each step
        while current_index < len(chain):
            block = chain[current_index]

            # Check hash pointer correctness
            if block["hash_of_previous_block"] != self.hash_block(last_block):
                return False

            # Check PoW validity for this block
            if not self.valid_proof(
                current_index,
                block["hash_of_previous_block"],
                block["transaction"],
                block["nonce"],
            ):
                return False

            last_block = block
            current_index += 1

        return True

    def update_blockchain(self):
        """
        Resolve conflicts by asking all neighbors for their chains and adopting
        the longest valid chain found (if any).

        Returns
        -------
        bool
            True if our chain was replaced; False if no replacement occurred.
        """
        neighbours = self.nodes
        new_chain = None

        # Only adopt a chain strictly longer than our own
        max_length = len(self.chain)

        for node in neighbours:
            # Query peer for its chain snapshot
            response = requests.get(f"http://{node}/blockchain")

            if response.status_code == 200:
                length = response.json()["length"]
                chain = response.json()["chain"]

                # Prefer a longer AND valid chain
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

                # If we found a valid longer chain, adopt it
                if new_chain:
                    self.chain = new_chain
                    return True

        return False

    # -----------------------------
    # Proof of Work (mining)
    # -----------------------------

    def proof_of_work(self, index, hash_of_previous_block, transactions):
        """
        Find a nonce that makes the block content hash satisfy the difficulty target.

        Mining loop:
        - Start nonce at 0
        - Increment until valid_proof(...) returns True

        Parameters
        ----------
        index : int
            The index the new block will have.
        hash_of_previous_block : str
            The hash pointer to the previous block.
        transactions : list[dict]
            The list of transactions to be included in the new block.

        Returns
        -------
        int
            A valid nonce for this block content.
        """
        nonce = 0
        while self.valid_proof(index, hash_of_previous_block, transactions, nonce) is False:
            nonce += 1
        return nonce

    def valid_proof(self, index, hash_of_previous_block, transactions, nonce):
        """
        Check whether the provided nonce makes the block content hash
        meet the difficulty target (leading zeros).

        Parameters
        ----------
        index : int
        hash_of_previous_block : str
        transactions : list[dict]
        nonce : int

        Returns
        -------
        bool
            True if SHA-256(content) starts with `difficulty_target`.
        """
        # Concatenate all critical fields and hash them
        content = f"{index}{hash_of_previous_block}{transactions}{nonce}".encode()
        content_hash = hashlib.sha256(content).hexdigest()

        # Difficulty check: prefix match
        return content_hash[: len(self.difficulty_target)] == self.difficulty_target

    # -----------------------------
    # Block / transaction handling
    # -----------------------------

    def append_block(self, nonce, hash_of_previous_block):
        """
        Append a new block to the chain, using the current transaction pool and
        the provided PoW nonce.

        Parameters
        ----------
        nonce : int
            A PoW nonce proven valid by `valid_proof(...)`.
        hash_of_previous_block : str
            Hash pointer to the previous block.

        Returns
        -------
        dict
            The newly created block.
        """
        block = {
            "index": len(self.chain),
            "timestamp": time(),  # UNIX epoch seconds (float)
            "transaction": self.current_transactions,  # all txns included in this block
            "nonce": nonce,
            "hash_of_previous_block": hash_of_previous_block,
        }

        # Reset the transaction pool; they are now confirmed in this block
        self.current_transactions = []

        # Append to the authoritative chain
        self.chain.append(block)
        return block

    def add_transaction(self, sender, recipient, amount):
        """
        Add a new transaction to the pool (unconfirmed).

        Parameters
        ----------
        sender : str
            Address of the sender (public key id or similar).
        recipient : str
            Address of the recipient.
        amount : int|float
            Amount/value transferred.

        Returns
        -------
        int
            The index of the block that will hold this transaction (next block).
        """
        self.current_transactions.append(
            {
                "amount": amount,
                "recipient": recipient,
                "sender": sender,
            }
        )
        return self.last_block["index"] + 1

    @property
    def last_block(self):
        """
        Return the most recently appended block.
        """
        return self.chain[-1]


# -----------------------------
# Flask application / endpoints
# -----------------------------

app = Flask(__name__)

# A unique identifier for this node (used to receive mining rewards).
node_identifier = str(uuid4()).replace("-", "")

# The single global blockchain instance for this process.
blockchain = Blockchain()


# routes
@app.route("/blockchain", methods=["GET"])
def full_chain():
    """
    Inspect the full blockchain (confirmed blocks only).

    Returns
    -------
    JSON
        {"chain": [...], "length": <int>}
    """
    response = {
        "chain": blockchain.chain,
        "length": len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route("/mine", methods=["GET"])
def mine_block():
    """
    Mine a new block:
    - Add a coinbase transaction (reward) to this node
    - Run PoW against the current mempool
    - Append the new block and return its summary
    """
    # "Coinbase" reward: sender "0" signifies newly minted coins
    blockchain.add_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    last_block_hash = blockchain.hash_block(blockchain.last_block)

    index = len(blockchain.chain)
    nonce = blockchain.proof_of_work(index, last_block_hash, blockchain.current_transactions)

    block = blockchain.append_block(nonce, last_block_hash)
    response = {
        "message": "Block baru telah ditambahkan (mined)",  # Indonesian: "New block has been mined"
        "index": block["index"],
        "hash_of_previous_block": block["hash_of_previous_block"],
        "nonce": block["nonce"],
        "transaction": block["transaction"],
    }

    return jsonify(response), 200


@app.route("/transactions/new", methods=["POST"])
def new_transaction():
    """
    Add a new transaction to the mempool.

    Body (JSON)
    -----------
    {
      "sender": "address",
      "recipient": "address",
      "amount": <number>
    }

    Returns
    -------
    201 + JSON message indicating the future block index.
    """
    values = request.get_json()

    required_fields = ["sender", "recipient", "amount"]
    if not values or not all(k in values for k in required_fields):
        return ("Missing fields", 400)

    index = blockchain.add_transaction(
        values["sender"],
        values["recipient"],
        values["amount"],
    )

    response = {"message": f"Transaksi akan ditambahkan ke blok {index}"}
    return (jsonify(response), 201)


@app.route("/nodes/add_nodes", methods=["POST"])
def add_nodes():
    """
    Register one or more peer nodes.

    Body (JSON)
    -----------
    { "nodes": ["127.0.0.1:5001", "example.com:5002", ...] }
    """
    values = request.get_json()
    nodes = values.get("nodes") if values else None

    if nodes is None:
        return "Error, missing node(s) info", 400

    for node in nodes:
        blockchain.add_node(node)

    response = {
        "message": "Node baru telah di tambahkan",
        "nodes": list(blockchain.nodes),
    }

    return jsonify(response), 200


@app.route("/nodes/sync", methods=["GET"])
def sync():
    """
    Resolve conflicts by fetching peers and adopting the longest valid chain.
    """
    updated = blockchain.update_blockchain()
    if updated:
        response = {
            "message": "Blockchain telah diupdate dengan data terbaru",
            "blockchain": blockchain.chain,
            "nodes": list(blockchain.nodes),
        }
    else:
        response = {
            "message": "Blockchain sudah menggunakan data paling baru",
            "blockchain": blockchain.chain,
            "nodes": list(blockchain.nodes),
        }
    return jsonify(response), 200


@app.route("/nodes", methods=["GET"])
def full_nodes():
    """
    List all known peer nodes (host:port).
    """
    response = {
        "nodes": list(blockchain.nodes),
    }
    return jsonify(response), 200


if __name__ == "__main__":
    # Accept port from CLI argument to run multiple peers:
    # Example: 
    # 
    # (5000 not working on windows)
    # python blockchain.py 5001 
    # or
    # python3 blockchain.py 5001 (use python3 for mac)
    # 
    app.run(host="0.0.0.0", port=int(sys.argv[1]))
