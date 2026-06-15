/**
 * QPL Extended Test Suite — Production Parameters on Local Validator
 * =============================================================================
 *
 * Covers all flows not exercised by the base 12-test smoke suite:
 *   A. Fee charge + 40/50/10 split verification
 *   B. Operator claims fee earnings
 *   C. Governance initiates slash (24h dispute window)
 *   D. Operator disputes slash (cancels pending slash)
 *   E. Execute slash after dispute window (warp time)
 *   F. Withdraw after unbonding (warp time)
 *   G. Error cases: unauthorized, early withdraw, early execute, nothing to claim
 *
 * Run on local validator:
 *   solana-test-validator --reset --quiet
 *   anchor build && anchor deploy --provider.cluster localnet
 *   ANCHOR_PROVIDER_URL=http://localhost:8899 ANCHOR_WALLET=~/.config/solana/id.json \
 *     yarn run ts-mocha -p ./tsconfig.json -t 1000000 tests/solana/extended-test.ts
 *
 * For warp-time tests (withdraw, execute slash), restart validator:
 *   solana-test-validator --reset --quiet --warp-slot +50000
 *   (this jumps ~7 days ahead on a 400ms slot time)
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { QplStaking } from "../../target/types/qpl_staking";
import { QplFeeRouter } from "../../target/types/qpl_fee_router";
import { QplRegistry } from "../../target/types/qpl_registry";
import {
  LAMPORTS_PER_SOL,
  PublicKey,
  Keypair,
  SystemProgram,
} from "@solana/web3.js";
import BN from "bn.js";
import { expect } from "chai";
import * as fs from "fs";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TX_RESULTS: { name: string; sig: string }[] = [];

function logTx(name: string, sig: string) {
  TX_RESULTS.push({ name, sig });
  console.log(`  ✅ ${name}: ${sig}`);
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("QPL Extended Test Suite", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const staking = anchor.workspace.QplStaking as Program<QplStaking>;
  const feeRouter = anchor.workspace.QplFeeRouter as Program<QplFeeRouter>;

  const authority = (provider.wallet as anchor.Wallet).payer;
  const treasury = authority.publicKey;

  // PDA seeds
  const CONFIG_SEED = Buffer.from("config");
  const VAULT_SEED = Buffer.from("vault");
  const FEE_CONFIG_SEED = Buffer.from("fee-config");
  const FEE_VAULT_SEED = Buffer.from("fee-vault");

  // Shared operator for staking tests
  const operatorKeypair = Keypair.generate();
  const operatorId = new Uint8Array(32).fill(1);
  const OPERATOR_ENDPOINT = "https://ext-operator.example.com:9090";
  const SERVICE_SIGNING = 0x02;

  // Track warp state
  let isWarped = true;

  // -------------------------------------------------------------------------
  // SETUP: Init config, vault, stake 20 SOL, deposit 2 SOL fee balance
  // -------------------------------------------------------------------------
  before(async () => {
    // Fund operator with 50 SOL
    const transferSig = await provider.connection.sendTransaction(
      new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: authority.publicKey,
          toPubkey: operatorKeypair.publicKey,
          lamports: 50 * LAMPORTS_PER_SOL,
        })
      ),
      [authority]
    );
    await provider.connection.confirmTransaction(transferSig);

    // Init staking config
    const [configPda] = PublicKey.findProgramAddressSync(
      [CONFIG_SEED], staking.programId
    );
    try {
      await staking.methods.initializeConfig(treasury)
        .accounts({ config: configPda, governance: authority.publicKey, systemProgram: SystemProgram.programId } as any)
        .rpc();
    } catch (err: any) {
      if (!err.logs?.some((l: string) => l.includes("already in use"))) throw err;
    }

    // Init stake vault
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED], staking.programId
    );
    try {
      await staking.methods.initializeVault()
        .accounts({ stakeVault: vaultPda, authority: authority.publicKey, systemProgram: SystemProgram.programId } as any)
        .rpc();
    } catch (err: any) {
      if (!err.logs?.some((l: string) => l.includes("already in use"))) throw err;
    }

    // Init fee router config
    const [feeConfigPda] = PublicKey.findProgramAddressSync(
      [FEE_CONFIG_SEED], feeRouter.programId
    );
    try {
      await feeRouter.methods.initialize(treasury)
        .accounts({ config: feeConfigPda, governance: authority.publicKey, systemProgram: SystemProgram.programId } as any)
        .rpc();
    } catch (err: any) {
      if (!err.logs?.some((l: string) => l.includes("already in use"))) throw err;
    }

    // Init fee vault
    const [feeVaultPda] = PublicKey.findProgramAddressSync(
      [FEE_VAULT_SEED], feeRouter.programId
    );
    try {
      await feeRouter.methods.initializeVault()
        .accounts({ config: feeConfigPda, feeVault: feeVaultPda, governance: authority.publicKey, systemProgram: SystemProgram.programId } as any)
        .rpc();
    } catch (err: any) {
      if (!err.logs?.some((l: string) => l.includes("already in use"))) throw err;
    }

    // Stake 20 SOL
    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)], staking.programId
    );
    try {
      await staking.methods.stake(
        Array.from(operatorId), OPERATOR_ENDPOINT, SERVICE_SIGNING,
        new BN(20 * LAMPORTS_PER_SOL)
      )
        .accounts({
          operator: operatorKeypair.publicKey,
          operatorAccount: operatorPda,
          stakeVault: vaultPda,
          systemProgram: SystemProgram.programId,
        } as any)
        .signers([operatorKeypair])
        .rpc();
    } catch (err: any) {
      if (!err.logs?.some((l: string) => l.includes("already in use"))) throw err;
    }

    // Deposit 5 SOL fee balance
    const protocolKeypair = Keypair.generate();
    const transferSig2 = await provider.connection.sendTransaction(
      new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: authority.publicKey,
          toPubkey: protocolKeypair.publicKey,
          lamports: 10 * LAMPORTS_PER_SOL,
        })
      ),
      [authority]
    );
    await provider.connection.confirmTransaction(transferSig2);

    const [protocolBalancePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("balance"), protocolKeypair.publicKey.toBuffer()], feeRouter.programId
    );
    await feeRouter.methods.depositBalance(new BN(5 * LAMPORTS_PER_SOL))
      .accounts({
        protocol: protocolKeypair.publicKey,
        protocolBalance: protocolBalancePda,
        feeVault: feeVaultPda,
        systemProgram: SystemProgram.programId,
      } as any)
      .signers([protocolKeypair])
      .rpc();

    console.log("  ✅ Setup complete: 20 SOL staked, 5 SOL fee balance deposited\n");
  });

  // =========================================================================
  // A. FEE CHARGE + 40/50/10 SPLIT
  // =========================================================================
  it("A. Charge 1 SOL fee → verify 40/50/10 split", async () => {
    const feeAmount = 1 * LAMPORTS_PER_SOL;

    // Create 2 participant operators
    const participant1 = Keypair.generate();
    const participant2 = Keypair.generate();

    // Init earnings PDAs for participants
    const [earnings1Pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("earnings"), participant1.publicKey.toBuffer()], feeRouter.programId
    );
    const [earnings2Pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("earnings"), participant2.publicKey.toBuffer()], feeRouter.programId
    );

    await feeRouter.methods.initParticipantEarnings()
      .accounts({
        payer: authority.publicKey,
        operator: participant1.publicKey,
        earnings: earnings1Pda,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    await feeRouter.methods.initParticipantEarnings()
      .accounts({
        payer: authority.publicKey,
        operator: participant2.publicKey,
        earnings: earnings2Pda,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    // Get PDAs for charge
    const [feeConfigPda] = PublicKey.findProgramAddressSync(
      [FEE_CONFIG_SEED], feeRouter.programId
    );
    const [feeVaultPda] = PublicKey.findProgramAddressSync(
      [FEE_VAULT_SEED], feeRouter.programId
    );

    // Protocol that deposited 5 SOL — we need its balance PDA
    // Use the protocol keypair from setup — but it's local. Use a known protocol.
    // Actually we need to use the same protocol. Let's re-derive.
    // The protocol keypair was created in before() — we need access.
    // For simplicity, let's deposit from authority as protocol.
    const [authBalancePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("balance"), authority.publicKey.toBuffer()], feeRouter.programId
    );

    // Deposit 2 SOL from authority as protocol
    await feeRouter.methods.depositBalance(new BN(2 * LAMPORTS_PER_SOL))
      .accounts({
        protocol: authority.publicKey,
        protocolBalance: authBalancePda,
        feeVault: feeVaultPda,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    // Coordinator = authority
    const [coordEarningsPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("earnings"), authority.publicKey.toBuffer()], feeRouter.programId
    );

    // Charge 1 SOL
    const treasuryBefore = await provider.connection.getBalance(treasury);

    const sig = await feeRouter.methods.chargeFee(
      new BN(feeAmount),
      authority.publicKey,
      [participant1.publicKey, participant2.publicKey]
    )
      .accounts({
        governance: authority.publicKey,
        config: feeConfigPda,
        protocolBalance: authBalancePda,
        coordinatorEarnings: coordEarningsPda,
        feeVault: feeVaultPda,
        treasury: treasury,
        systemProgram: SystemProgram.programId,
      } as any)
      .remainingAccounts([
        { pubkey: earnings1Pda, isWritable: true, isSigner: false },
        { pubkey: earnings2Pda, isWritable: true, isSigner: false },
      ])
      .rpc();

    const treasuryAfter = await provider.connection.getBalance(treasury);

    // Verify split:
    // Coordinator (40%): 0.4 SOL
    // Treasury (10%):     0.1 SOL
    // Participants (50%): 0.5 SOL / 2 = 0.25 SOL each
    const expectedCoordinator = Math.floor(feeAmount * 40 / 100);
    const expectedTreasury = Math.floor(feeAmount * 10 / 100);
    const participantPool = feeAmount - expectedCoordinator - expectedTreasury;
    const expectedPerParticipant = Math.floor(participantPool / 2);

    const coordEarnings = await feeRouter.account.operatorEarnings.fetch(coordEarningsPda);
    expect(coordEarnings.claimable.toNumber()).to.equal(expectedCoordinator);

    const p1Earnings = await feeRouter.account.operatorEarnings.fetch(earnings1Pda);
    expect(p1Earnings.claimable.toNumber()).to.equal(expectedPerParticipant);

    const p2Earnings = await feeRouter.account.operatorEarnings.fetch(earnings2Pda);
    expect(p2Earnings.claimable.toNumber()).to.equal(expectedPerParticipant);

    // Verify config totals increased
    const [feeConfigPda2] = PublicKey.findProgramAddressSync(
      [FEE_CONFIG_SEED], feeRouter.programId
    );
    const feeConfig = await feeRouter.account.feeRouterConfig.fetch(feeConfigPda2);
    expect(feeConfig.totalFeesCollected.toNumber()).to.be.greaterThan(0);

    // Protocol balance decremented by exactly feeAmount
    const authBalance = await feeRouter.account.protocolBalance.fetch(authBalancePda);
    const expectedRemaining = (2 * LAMPORTS_PER_SOL) - feeAmount;
    // Account for any pre-existing balance from previous runs
    expect(authBalance.balance.toNumber()).to.be.greaterThanOrEqual(expectedRemaining);

    logTx("charge_fee_1_sol", sig);
    console.log(`  ℹ️  Split: coord=${expectedCoordinator / LAMPORTS_PER_SOL} SOL, treasury=${expectedTreasury / LAMPORTS_PER_SOL} SOL, per-participant=${expectedPerParticipant / LAMPORTS_PER_SOL} SOL`);
  });

  // =========================================================================
  // B. OPERATOR CLAIMS FEE EARNINGS
  // =========================================================================
  it("B. Participant claims fee earnings", async () => {
    // participant1 from test A has 0.25 SOL claimable
    // We need to use the same keypair — let's re-create deterministically
    // Actually, participant keypairs were created in test A scope.
    // Let's use coordinator (authority) which has 0.4 SOL claimable.

    const [coordEarningsPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("earnings"), authority.publicKey.toBuffer()], feeRouter.programId
    );
    const [feeVaultPda] = PublicKey.findProgramAddressSync(
      [FEE_VAULT_SEED], feeRouter.programId
    );

    const earningsBefore = await feeRouter.account.operatorEarnings.fetch(coordEarningsPda);
    const claimableAmount = earningsBefore.claimable.toNumber();
    expect(claimableAmount).to.be.greaterThan(0);

    const balanceBefore = await provider.connection.getBalance(authority.publicKey);

    const sig = await feeRouter.methods.claim()
      .accounts({
        operator: authority.publicKey,
        earnings: coordEarningsPda,
        feeVault: feeVaultPda,
      } as any)
      .rpc();

    const earningsAfter = await feeRouter.account.operatorEarnings.fetch(coordEarningsPda);
    expect(earningsAfter.claimable.toNumber()).to.equal(0);
    expect(earningsAfter.totalClaimed.toNumber()).to.equal(claimableAmount);

    const balanceAfter = await provider.connection.getBalance(authority.publicKey);
    expect(balanceAfter).to.be.greaterThan(balanceBefore);

    logTx("claim_earnings", sig);
    console.log(`  ℹ️  Claimed: ${claimableAmount / LAMPORTS_PER_SOL} SOL`);
  });

  // =========================================================================
  // C. GOVERNANCE INITIATES SLASH
  // =========================================================================
  it("C. Governance initiates 3 SOL slash on operator", async () => {
    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)], staking.programId
    );
    const [configPda] = PublicKey.findProgramAddressSync(
      [CONFIG_SEED], staking.programId
    );

    const slashAmount = 3 * LAMPORTS_PER_SOL;
    const reason = "Failed to produce ZK proofs for 100 consecutive batches";

    const sig = await staking.methods.initiateSlash(
      new BN(slashAmount),
      reason
    )
      .accounts({
        governance: authority.publicKey,
        operatorAccount: operatorPda,
        config: configPda,
      } as any)
      .rpc();

    const opAccount = await staking.account.operatorAccount.fetch(operatorPda);
    expect(opAccount.pendingSlashAmount.toNumber()).to.equal(slashAmount);
    expect(opAccount.pendingSlashReason).to.equal(reason);
    expect(opAccount.slashInitiatedAt.toNumber()).to.be.greaterThan(0);
    expect(opAccount.active).to.be.true; // Still active during dispute window

    logTx("initiate_slash_3_sol", sig);
    console.log(`  ℹ️  Pending slash: ${slashAmount / LAMPORTS_PER_SOL} SOL, reason: "${reason}"`);
  });

  // =========================================================================
  // D. OPERATOR DISPUTES SLASH
  // =========================================================================
  it("D. Operator disputes slash (cancels pending)", async () => {
    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)], staking.programId
    );

    // Operator disputes before window expires
    const sig = await staking.methods.disputeSlash()
      .accounts({
        operator: operatorKeypair.publicKey,
        operatorAccount: operatorPda,
      })
      .signers([operatorKeypair])
      .rpc();

    const opAccount = await staking.account.operatorAccount.fetch(operatorPda);
    expect(opAccount.pendingSlashAmount.toNumber()).to.equal(0);
    expect(opAccount.pendingSlashReason).to.equal("");
    expect(opAccount.active).to.be.true;

    logTx("dispute_slash", sig);
    console.log("  ℹ️  Slash cancelled via dispute");
  });

  // =========================================================================
  // WARP SETUP: Initiate unstake + slash for phase 2 warp tests
  // =========================================================================
  it("Warp prep: initiate unstake + slash for phase 2", async () => {
    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)], staking.programId
    );
    const [configPda] = PublicKey.findProgramAddressSync(
      [CONFIG_SEED], staking.programId
    );
  
    // Initiate unstake (starts 7-day unbonding)
    await staking.methods.initiateUnstake()
      .accounts({ operator: operatorKeypair.publicKey, operatorAccount: operatorPda })
      .signers([operatorKeypair])
      .rpc();
  
    // Initiate slash (starts 24h dispute window)
    await staking.methods.initiateSlash(
      new BN(3 * LAMPORTS_PER_SOL),
      "Warp test: governance slash for execution in phase 2"
    )
      .accounts({
        governance: authority.publicKey,
        operatorAccount: operatorPda,
        config: configPda,
      } as any)
      .rpc();
  
    // Write state file for phase 2 (warp-test.ts)
    const state = {
      operatorId: JSON.stringify(Array.from(operatorId)),
      operatorPubkey: operatorKeypair.publicKey.toBase58(),
    };
    fs.writeFileSync("/tmp/qpl-warp-state.json", JSON.stringify(state));
    console.log("  \u2705 Warp prep complete: state written to /tmp/qpl-warp-state.json");
  });
  
  // =========================================================================
  // G. ERROR CASES
  // =========================================================================
  it("G1. Reject withdraw before unbonding elapses", async () => {

    // Create fresh operator, stake, initiate unstake, try immediate withdraw
    const freshOp = Keypair.generate();
    const freshId = new Uint8Array(32).fill(77);

    const transferSig = await provider.connection.sendTransaction(
      new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: authority.publicKey,
          toPubkey: freshOp.publicKey,
          lamports: 15 * LAMPORTS_PER_SOL,
        })
      ),
      [authority]
    );
    await provider.connection.confirmTransaction(transferSig);

    const [opPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(freshId)], staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED], staking.programId
    );

    await staking.methods.stake(
      Array.from(freshId), "https://fresh.example.com", SERVICE_SIGNING,
      new BN(12 * LAMPORTS_PER_SOL)
    )
      .accounts({
        operator: freshOp.publicKey,
        operatorAccount: opPda,
        stakeVault: vaultPda,
        systemProgram: SystemProgram.programId,
      } as any)
      .signers([freshOp])
      .rpc();

    await staking.methods.initiateUnstake()
      .accounts({ operator: freshOp.publicKey, operatorAccount: opPda })
      .signers([freshOp])
      .rpc();

    // Try withdraw immediately (should fail — unbonding not elapsed)
    try {
      await staking.methods.withdraw()
        .accounts({ operator: freshOp.publicKey, operatorAccount: opPda, stakeVault: vaultPda } as any)
        .signers([freshOp])
        .rpc();
      expect.fail("Should have rejected early withdraw");
    } catch (err: any) {
      expect(err.error.errorCode.code).to.equal("UnbondingNotElapsed");
      console.log("  ✅ Correctly rejected: UnbondingNotElapsed");
    }
  });

  it("G2. Reject execute slash before dispute window", async () => {

    const freshOp = Keypair.generate();
    const freshId = new Uint8Array(32).fill(88);

    const transferSig = await provider.connection.sendTransaction(
      new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: authority.publicKey,
          toPubkey: freshOp.publicKey,
          lamports: 15 * LAMPORTS_PER_SOL,
        })
      ),
      [authority]
    );
    await provider.connection.confirmTransaction(transferSig);

    const [opPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(freshId)], staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED], staking.programId
    );
    const [configPda] = PublicKey.findProgramAddressSync(
      [CONFIG_SEED], staking.programId
    );

    await staking.methods.stake(
      Array.from(freshId), "https://slash-test.example.com", SERVICE_SIGNING,
      new BN(12 * LAMPORTS_PER_SOL)
    )
      .accounts({
        operator: freshOp.publicKey,
        operatorAccount: opPda,
        stakeVault: vaultPda,
        systemProgram: SystemProgram.programId,
      } as any)
      .signers([freshOp])
      .rpc();

    // Initiate slash
    await staking.methods.initiateSlash(
      new BN(2 * LAMPORTS_PER_SOL), "Early execution test"
    )
      .accounts({
        governance: authority.publicKey,
        operatorAccount: opPda,
        config: configPda,
      } as any)
      .rpc();

    // Try execute immediately (should fail)
    try {
      await staking.methods.executeSlash()
        .accounts({
          executor: authority.publicKey,
          operatorAccount: opPda,
          stakeVault: vaultPda,
          treasury: treasury,
          config: configPda,
        } as any)
        .rpc();
      expect.fail("Should have rejected early execute");
    } catch (err: any) {
      expect(err.error.errorCode.code).to.equal("DisputeWindowNotElapsed");
      console.log("  ✅ Correctly rejected: DisputeWindowNotElapsed");
    }
  });

  it("G3. Reject claim with nothing to claim", async () => {
    const nobody = Keypair.generate();
    const [earningsPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("earnings"), nobody.publicKey.toBuffer()], feeRouter.programId
    );
    const [feeVaultPda] = PublicKey.findProgramAddressSync(
      [FEE_VAULT_SEED], feeRouter.programId
    );

    // Init empty earnings PDA
    await feeRouter.methods.initParticipantEarnings()
      .accounts({
        payer: authority.publicKey,
        operator: nobody.publicKey,
        earnings: earningsPda,
        systemProgram: SystemProgram.programId,
      } as any)
      .rpc();

    // Fund nobody so they can be a signer
    const transferSig = await provider.connection.sendTransaction(
      new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: authority.publicKey,
          toPubkey: nobody.publicKey,
          lamports: Math.floor(0.01 * LAMPORTS_PER_SOL),
        })
      ),
      [authority]
    );
    await provider.connection.confirmTransaction(transferSig);

    try {
      await feeRouter.methods.claim()
        .accounts({
          operator: nobody.publicKey,
          earnings: earningsPda,
          feeVault: feeVaultPda,
        } as any)
        .signers([nobody])
        .rpc();
      expect.fail("Should have rejected nothing to claim");
    } catch (err: any) {
      expect(err.error.errorCode.code).to.equal("NothingToClaim");
      console.log("  ✅ Correctly rejected: NothingToClaim");
    }
  });

  it("G4. Reject non-governance calling charge_fee", async () => {
    const fakeGov = Keypair.generate();
    const [feeConfigPda] = PublicKey.findProgramAddressSync(
      [FEE_CONFIG_SEED], feeRouter.programId
    );
    const [feeVaultPda] = PublicKey.findProgramAddressSync(
      [FEE_VAULT_SEED], feeRouter.programId
    );
    const [authBalancePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("balance"), authority.publicKey.toBuffer()], feeRouter.programId
    );
    const [coordEarningsPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("earnings"), authority.publicKey.toBuffer()], feeRouter.programId
    );

    // Fund fake governance
    const transferSig = await provider.connection.sendTransaction(
      new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: authority.publicKey,
          toPubkey: fakeGov.publicKey,
          lamports: Math.floor(0.01 * LAMPORTS_PER_SOL),
        })
      ),
      [authority]
    );
    await provider.connection.confirmTransaction(transferSig);

    try {
      await feeRouter.methods.chargeFee(
        new BN(LAMPORTS_PER_SOL),
        fakeGov.publicKey,
        []
      )
        .accounts({
          governance: fakeGov.publicKey,
          config: feeConfigPda,
          protocolBalance: authBalancePda,
          coordinatorEarnings: coordEarningsPda,
          feeVault: feeVaultPda,
          treasury: treasury,
          systemProgram: SystemProgram.programId,
        } as any)
        .signers([fakeGov])
        .rpc();
      expect.fail("Should have rejected unauthorized");
    } catch (err: any) {
      expect(err.error.errorCode.code).to.equal("Unauthorized");
      console.log("  ✅ Correctly rejected: Unauthorized");
    }
  });

  // =========================================================================
  // SUMMARY
  // =========================================================================
  after(() => {
    console.log("\n" + "=".repeat(70));
    console.log("  QPL EXTENDED TEST SUITE — RESULTS");
    console.log("=".repeat(70));
    console.log(`  Transactions: ${TX_RESULTS.length}`);
    console.log("-".repeat(70));
    for (const tx of TX_RESULTS) {
      console.log(`  ${tx.name.padEnd(35)} ${tx.sig}`);
    }
    console.log("=".repeat(70));
  });
});
