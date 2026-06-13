# QPL Protocol Flows

Mermaid diagrams illustrating the core protocol flows of the QPL Network.

---

## 1. System Architecture

End-to-end view of how applications, operators, and the Solana settlement layer interact.

```mermaid
flowchart TB
    subgraph App["Applications"]
        DApp[DeFi / Wallet / Bridge]
    end

    subgraph Net["QPL Operator Network"]
        Coord[Coordinator<br/>quorum selection · fee routing]
        N1[Operator 1<br/>HSM + Prover]
        N2[Operator 2<br/>HSM + Prover]
        N3[Operator 3<br/>HSM + Prover]
        Nn[Operator N<br/>HSM + Prover]
    end

    subgraph Solana["Solana Settlement"]
        Reg[QPLRegistry]
        Stake[QPLStaking]
        Fee[QPLFeeRouter]
    end

    DApp -->|JSON-RPC / SDK| Coord
    Coord <-->|sign / prove RPC| N1
    Coord <-->|sign / prove RPC| N2
    Coord <-->|sign / prove RPC| N3
    Coord <-->|sign / prove RPC| Nn

    N1 -.->|register endpoint| Reg
    N2 -.->|register endpoint| Reg
    N3 -.->|register endpoint| Reg
    Nn -.->|register endpoint| Reg

    N1 -.->|deposit stake| Stake
    N2 -.->|deposit stake| Stake
    N3 -.->|deposit stake| Stake

    Coord -->|distribute fees| Fee
    Fee -->|40% / 50% / 10%| N1
```

---

## 2. Threshold Signing Flow (with Algorithmic Agility)

A single signing request, fanned out to a `t-of-n` quorum, with each operator using its HSM-resident key.

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant SDK as QPL SDK
    participant Coord as Coordinator
    participant Reg as Registry (Solana)
    participant Op1 as Operator 1
    participant Op2 as Operator 2
    participant Op3 as Operator 3
    participant HSM1 as HSM 1
    participant HSM2 as HSM 2
    participant HSM3 as HSM 3

    Client->>SDK: sign(message)
    SDK->>Coord: SignRequest{msg, algo_pref}
    Coord->>Reg: query active operators
    Reg-->>Coord: operator set + supported_algos
    Coord->>Coord: negotiate algorithm<br/>(Ed25519 / EcdsaP256 / MlDsa65)
    Coord->>Coord: select t-of-n quorum

    par Quorum fan-out
        Coord->>Op1: sign_shard(msg, algo)
        Op1->>HSM1: sign_agile(handle, msg)
        HSM1-->>Op1: AgileSignature shard 1
        Op1-->>Coord: shard 1
    and
        Coord->>Op2: sign_shard(msg, algo)
        Op2->>HSM2: sign_agile(handle, msg)
        HSM2-->>Op2: AgileSignature shard 2
        Op2-->>Coord: shard 2
    and
        Coord->>Op3: sign_shard(msg, algo)
        Op3->>HSM3: sign_agile(handle, msg)
        HSM3-->>Op3: AgileSignature shard 3
        Op3-->>Coord: shard 3
    end

    Coord->>Coord: combine shards →<br/>threshold signature
    Coord-->>SDK: AggregateSignature
    SDK-->>Client: signature
    Coord->>Coord: emit fee event
```

---

## 3. Algorithmic Agility — Algorithm Selection

How an operator advertises capability and how the coordinator picks the strongest mutually-supported algorithm.

```mermaid
flowchart LR
    Start([Sign request received]) --> Pref{Client<br/>preference?}
    Pref -->|MlDsa65| WantPQ[Prefer post-quantum]
    Pref -->|None| WantPQ
    Pref -->|Ed25519| WantClassic[Prefer classical]

    WantPQ --> CheckPQ{Quorum HSMs<br/>support FIPS 204?}
    CheckPQ -->|Yes| UsePQ[Use ML-DSA-65<br/>post-quantum]
    CheckPQ -->|No| FallbackPQ{Allow<br/>fallback?}
    FallbackPQ -->|Yes| UseEd[Use Ed25519<br/>HSM-native today]
    FallbackPQ -->|No| Reject[Reject<br/>AlgorithmNotSupported]

    WantClassic --> CheckEd{Quorum HSMs<br/>support Ed25519?}
    CheckEd -->|Yes| UseEd
    CheckEd -->|No| CheckEC{Quorum HSMs<br/>support P-256?}
    CheckEC -->|Yes| UseEC[Use ECDSA-P256<br/>FIPS 186-4]
    CheckEC -->|No| Reject

    UsePQ --> Done([sign_agile dispatched])
    UseEd --> Done
    UseEC --> Done
```

---

## 4. STARK Proving Flow

Proof generation for an arbitrary statement (e.g. a rollup batch or off-chain compute).

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant SDK as QPL SDK
    participant Coord as Coordinator
    participant Prover as Operator (Prover)
    participant Verifier as On-chain Verifier

    Client->>SDK: prove(statement, witness)
    SDK->>Coord: ProveRequest
    Coord->>Coord: select prover<br/>(reputation + load)
    Coord->>Prover: prove(statement, witness)

    Prover->>Prover: build AIR trace
    Prover->>Prover: commit trace (Merkle)
    Prover->>Prover: evaluate constraints
    Prover->>Prover: FRI low-degree proof
    Prover->>Prover: Fiat-Shamir transcript
    Prover-->>Coord: STARK proof π

    Coord-->>SDK: π
    SDK-->>Client: π

    opt On-chain settlement
        Client->>Verifier: verify(statement, π)
        Verifier-->>Client: accept / reject
    end
```

---

## 5. Operator Lifecycle (Staking State Machine)

```mermaid
stateDiagram-v2
    [*] --> Unregistered

    Unregistered --> Staked: deposit ≥ 10 SOL<br/>QPLStaking::stake
    Staked --> Joined: register endpoint<br/>QPLRegistry::join
    Joined --> Active: heartbeat OK<br/>quorum eligible
    Active --> Active: serve sign / prove<br/>earn fees

    Active --> Draining: request_exit
    Draining --> Exited: 7-day cooldown<br/>QPLStaking::withdraw
    Exited --> [*]

    Active --> Slashed: misbehavior detected<br/>QPLStaking::slash
    Draining --> Slashed: misbehavior detected
    Slashed --> Exited: residual stake returned

    note right of Slashed
        Slashable offenses:
        • equivocation
        • invalid signature shard
        • invalid proof
        • liveness failure
    end note
```

---

## 6. Slashing Flow

End-to-end path from misbehavior detection to on-chain stake reduction.

```mermaid
sequenceDiagram
    autonumber
    participant Watcher as Watcher / Operator
    participant Gov as Governance Multisig
    participant Stake as QPLStaking Program
    participant Treasury as Protocol Treasury
    participant Bad as Misbehaving Operator

    Watcher->>Watcher: observe equivocation /<br/>invalid shard
    Watcher->>Gov: submit fraud proof
    Gov->>Gov: verify evidence

    alt Evidence valid
        Gov->>Stake: slash(operator, amount)
        Stake->>Stake: load StakingConfig PDA
        Stake->>Stake: verify governance signer
        Stake->>Stake: checked_sub(stake, amount)
        Stake->>Treasury: transfer slashed lamports
        Stake-->>Gov: SlashEvent emitted
        Stake->>Bad: state → Slashed
    else Evidence invalid
        Gov-->>Watcher: reject
    end
```

---

## 7. Fee Routing Flow

How a single operation fee is split among coordinator, operators, and treasury.

```mermaid
flowchart LR
    Req[Signing or<br/>Proving Request] -->|~$0.001 fee| Router[QPLFeeRouter]

    Router -->|40%| Coord[Coordinator]
    Router -->|50%| Pool[Operator Pool]
    Router -->|10%| Treasury[Protocol Treasury]

    Pool -->|pro-rata by<br/>shards contributed| Op1[Operator 1]
    Pool -->|pro-rata| Op2[Operator 2]
    Pool -->|pro-rata| OpN[Operator N]

    classDef money fill:#1f3a1f,stroke:#4ade80,color:#d1fae5;
    class Router,Pool,Treasury,Coord,Op1,Op2,OpN money;
```

---

## 8. Key Lifecycle Inside an Operator HSM

What happens to a signing key from generation to use — the key never leaves the HSM.

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Operator Admin
    participant Node as Operator Node
    participant Provider as HsmProvider trait
    participant HSM as HSM (PKCS#11)

    Admin->>Node: enroll(algorithm)
    Node->>Provider: supported_signing_algorithms()
    Provider->>HSM: query mechanisms
    HSM-->>Provider: [Ed25519, EcdsaP256, ...]
    Provider-->>Node: capability list

    Node->>Provider: generate_signing_keypair(algo)
    Provider->>HSM: C_GenerateKeyPair
    HSM-->>Provider: KeyHandle (opaque)
    Provider-->>Node: KeyHandle

    Node->>Provider: export_public_key(handle)
    Provider->>HSM: C_GetAttributeValue (CKA_PUBLIC)
    HSM-->>Provider: AgilePublicKey
    Provider-->>Node: AgilePublicKey
    Node->>Node: register pubkey on-chain

    loop Each request
        Node->>Provider: sign_agile(handle, msg)
        Provider->>HSM: C_Sign
        HSM-->>Provider: AgileSignature
        Provider-->>Node: AgileSignature
    end

    Note over HSM: Private key material<br/>NEVER leaves the HSM boundary
```

---

## 9. End-to-End Request: SDK → Operator → Solana

A full happy-path trace combining signing, settlement, and fee distribution.

```mermaid
sequenceDiagram
    autonumber
    participant App as Application
    participant SDK as QPL SDK
    participant Coord as Coordinator
    participant Quorum as Operator Quorum (t-of-n)
    participant Solana as Solana Programs

    App->>SDK: sign(payload)
    SDK->>Coord: SignRequest

    Coord->>Solana: query QPLRegistry (active set)
    Solana-->>Coord: operators + algos
    Coord->>Quorum: fan-out sign_shard
    Quorum-->>Coord: t valid shards
    Coord->>Coord: combine threshold signature
    Coord-->>SDK: signature

    par Settlement
        Coord->>Solana: QPLFeeRouter::distribute
        Solana-->>Solana: pay coord 40% / ops 50% / treasury 10%
    and Receipt
        SDK-->>App: signature + receipt
    end
```

---

## 10. Post-Quantum Migration Path

How operators transition from Ed25519 today to ML-DSA-65 when FIPS 204 firmware ships, with zero protocol downtime.

```mermaid
flowchart TB
    Today[Today<br/>Ed25519 / ECDSA-P256<br/>HSM-native, FIPS 140-3] --> Hybrid

    subgraph Hybrid["Migration Window — Mixed Quorum"]
        direction LR
        H1[Operator A<br/>Ed25519] -.->|both shards verify| Combine
        H2[Operator B<br/>Ed25519] -.->|both shards verify| Combine
        H3[Operator C<br/>ML-DSA-65] -.->|both shards verify| Combine
        Combine[Coordinator negotiates<br/>per-request algorithm]
    end

    Hybrid --> Future[Future<br/>ML-DSA-65 default<br/>Ed25519 deprecated]

    classDef now fill:#1e3a8a,stroke:#60a5fa,color:#dbeafe;
    classDef mid fill:#78350f,stroke:#fbbf24,color:#fef3c7;
    classDef next fill:#14532d,stroke:#4ade80,color:#d1fae5;
    class Today now;
    class Hybrid,Combine,H1,H2,H3 mid;
    class Future next;
```

---

## Rendering

These diagrams render natively on:

- GitHub / GitLab (Markdown)
- VS Code with the Markdown Preview Mermaid extension
- mermaid.live (paste any block to edit interactively)
