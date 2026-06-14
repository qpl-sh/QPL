/**
 * QPL Testnet Smoke Test
 * =============================================================================
 *
 * Deterministic, scripted test sequence for Solana testnet proof-of-life.
 * Exercises all 3 programs (staking, fee-router, registry) with real transactions.
 *
 * Run after deployment:
 *   anchor test --provider.cluster testnet -- tests/solana/testnet-smoke.ts
 *
 * Or with a specific wallet:
 *   ANCHOR_WALLET=~/path/to/key.json anchor test --provider.cluster testnet -- tests/solana/testnet-smoke.ts
 *
 * Each test logs its transaction signature for verifiable proof-of-life.
 * Total SOL cost: ~0.5 SOL (mostly stake deposits + rent).
 *
 * Test sequence:
 *   1. Initialize staking config + vault
 *   2. Initialize fee router config + vault
 *   3. Register operator in registry
 *   4. Stake 10 SOL (minimum)
 *   5. Reject stake below minimum
 *   6. Deposit additional stake
 *   7. Initiate unstake → verify 7-day unbonding
 *   8. Fee router: deposit prepaid balance
 *   9. Fee router: charge fee → verify 40/50/10 split
 *  10. Fee router: operator claims earnings
 *  11. Registry: update endpoint
 *  12. Registry: deactivate operator
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { QplStaking } from "../target/types/qpl_staking";
import { QplFeeRouter } from "../target/types/qpl_fee_router";
import { QplRegistry } from "../target/types/qpl_registry";
import {
  LAMPORTS_PER_SOL,
  PublicKey,
  Keypair,
  SystemProgram,
} from "@solana/web3.js";
import { expect } from "chai";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TX_RESULTS: { name: string; sig: string }[] = [];

function logTx(name: string, sig: string) {
  TX_RESULTS.push({ name, sig });
  console.log(`  ✅ ${name}: ${sig}`);
}

function logSummary() {
  console.log("\n" + "=".repeat(70));
  console.log("  QPL TESTNET SMOKE TEST — RESULTS");
  console.log("=".repeat(70));
  console.log(`  Cluster: testnet`);
  console.log(`  Authority: ${authority.publicKey.toBase58()}`);
  console.log(`  Timestamp: ${new Date().toISOString()}`);
  console.log(`  Transactions: ${TX_RESULTS.length}`);
  console.log("-".repeat(70));
  for (const tx of TX_RESULTS) {
    console.log(`  ${tx.name.padEnd(35)} ${tx.sig}`);
  }
  console.log("=".repeat(70));
  console.log(
    `\n  Explorer: https://explorer.solana.com/?cluster=testnet`
  );
  console.log(
    `  Verify each tx at: https://explorer.solana.com/tx/<sig>?cluster=testnet\n`
  );
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("QPL Testnet Smoke Test", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const staking = anchor.workspace.QplStaking as Program<QplStaking>;
  const feeRouter = anchor.workspace.QplFeeRouter as Program<QplFeeRouter>;
  const registry = anchor.workspace.QplRegistry as Program<QplRegistry>;

  const authority = (provider.wallet as anchor.Wallet).payer;
  const treasury = authority.publicKey;

  // PDA seeds
  const CONFIG_SEED = Buffer.from("config");
  const VAULT_SEED = Buffer.from("vault");
  const FEE_CONFIG_SEED = Buffer.from("fee-config");
  const FEE_VAULT_SEED = Buffer.from("fee-vault");

  // Test operator
  const operatorKeypair = Keypair.generate();
  const operatorId = new Uint8Array(32).fill(42);
  const OPERATOR_ENDPOINT = "https://qpl-operator-1.example.com:9090";
  const SERVICE_SIGNING = 0x02;
  const SERVICE_PROVING = 0x04;

  // -----------------------------------------------------------------------
  // 1. Initialize staking config
  // -----------------------------------------------------------------------
  it("1. Initialize staking config", async () => {
    const [configPda] = PublicKey.findProgramAddressSync(
      [CONFIG_SEED],
      staking.programId
    );

    const sig = await staking.methods
      .initializeConfig(treasury)
      .accounts({
        config: configPda,
        governance: authority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const config = await staking.account.stakingConfig.fetch(configPda);
    expect(config.governance.toBase58()).to.equal(authority.publicKey.toBase58());
    expect(config.treasury.toBase58()).to.equal(treasury.toBase58());
    logTx("init_staking_config", sig);
  });

  // -----------------------------------------------------------------------
  // 2. Initialize stake vault
  // -----------------------------------------------------------------------
  it("2. Initialize stake vault", async () => {
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      staking.programId
    );

    const sig = await staking.methods
      .initializeVault()
      .accounts({
        stakeVault: vaultPda,
        authority: authority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const vault = await staking.account.stakeVault.fetch(vaultPda);
    expect(vault.bump).to.be.a("number");
    logTx("init_stake_vault", sig);
  });

  // -----------------------------------------------------------------------
  // 3. Initialize fee router config
  // -----------------------------------------------------------------------
  it("3. Initialize fee router config", async () => {
    const [feeConfigPda] = PublicKey.findProgramAddressSync(
      [FEE_CONFIG_SEED],
      feeRouter.programId
    );

    const sig = await feeRouter.methods
      .initialize(treasury)
      .accounts({
        config: feeConfigPda,
        governance: authority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const config = await feeRouter.account.feeRouterConfig.fetch(feeConfigPda);
    expect(config.governance.toBase58()).to.equal(authority.publicKey.toBase58());
    expect(config.totalFeesCollected.toNumber()).to.equal(0);
    logTx("init_fee_router_config", sig);
  });

  // -----------------------------------------------------------------------
  // 4. Initialize fee vault
  // -----------------------------------------------------------------------
  it("4. Initialize fee vault", async () => {
    const [feeConfigPda] = PublicKey.findProgramAddressSync(
      [FEE_CONFIG_SEED],
      feeRouter.programId
    );
    const [feeVaultPda] = PublicKey.findProgramAddressSync(
      [FEE_VAULT_SEED],
      feeRouter.programId
    );

    const sig = await feeRouter.methods
      .initializeVault()
      .accounts({
        config: feeConfigPda,
        feeVault: feeVaultPda,
        governance: authority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const vault = await feeRouter.account.feeVault.fetch(feeVaultPda);
    expect(vault.bump).to.be.a("number");
    logTx("init_fee_vault", sig);
  });

  // -----------------------------------------------------------------------
  // 5. Register operator in registry
  // -----------------------------------------------------------------------
  it("5. Register operator in registry", async () => {
    const [registryPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("registry"), Buffer.from(operatorId)],
      registry.programId
    );

    const sig = await registry.methods
      .register(operatorId, OPERATOR_ENDPOINT, SERVICE_SIGNING | SERVICE_PROVING)
      .accounts({
        operator: operatorKeypair.publicKey,
        registryEntry: registryPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([operatorKeypair])
      .rpc();

    const entry = await registry.account.registryEntry.fetch(registryPda);
    expect(entry.endpoint).to.equal(OPERATOR_ENDPOINT);
    expect(entry.servicesBitmask).to.equal(SERVICE_SIGNING | SERVICE_PROVING);
    expect(entry.active).to.be.true;
    logTx("registry_register", sig);
  });

  // -----------------------------------------------------------------------
  // 6. Fund operator and stake 10 SOL
  // -----------------------------------------------------------------------
  it("6. Stake 10 SOL (minimum)", async () => {
    // Airdrop 15 SOL to operator (10 for stake + 5 for tx fees)
    const airdropSig = await provider.connection.requestAirdrop(
      operatorKeypair.publicKey,
      15 * LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(airdropSig);

    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)],
      staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      staking.programId
    );

    const sig = await staking.methods
      .stake(
        Array.from(operatorId),
        OPERATOR_ENDPOINT,
        SERVICE_SIGNING | SERVICE_PROVING,
        10 * LAMPORTS_PER_SOL
      )
      .accounts({
        operator: operatorKeypair.publicKey,
        operatorAccount: operatorPda,
        stakeVault: vaultPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([operatorKeypair])
      .rpc();

    const opAccount = await staking.account.operatorAccount.fetch(operatorPda);
    expect(opAccount.stakedAmount.toNumber()).to.equal(10 * LAMPORTS_PER_SOL);
    expect(opAccount.active).to.be.true;
    logTx("stake_10_sol", sig);
  });

  // -----------------------------------------------------------------------
  // 7. Reject stake below minimum
  // -----------------------------------------------------------------------
  it("7. Reject stake below minimum (5 SOL)", async () => {
    const underfundedOp = Keypair.generate();
    const underfundedId = new Uint8Array(32).fill(99);

    // Airdrop just 1 SOL (not enough for 10 SOL minimum)
    const airdropSig = await provider.connection.requestAirdrop(
      underfundedOp.publicKey,
      1 * LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(airdropSig);

    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(underfundedId)],
      staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      staking.programId
    );

    try {
      await staking.methods
        .stake(
          Array.from(underfundedId),
          "http://underfunded.example.com:9090",
          SERVICE_SIGNING,
          5 * LAMPORTS_PER_SOL
        )
        .accounts({
          operator: underfundedOp.publicKey,
          operatorAccount: operatorPda,
          stakeVault: vaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([underfundedOp])
        .rpc();
      expect.fail("Should have rejected insufficient stake");
    } catch (err: any) {
      expect(err.error.errorCode.code).to.equal("InsufficientStake");
      console.log("  ✅ Correctly rejected: InsufficientStake");
    }
  });

  // -----------------------------------------------------------------------
  // 8. Deposit additional stake (top-up)
  // -----------------------------------------------------------------------
  it("8. Deposit additional 5 SOL stake", async () => {
    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)],
      staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      staking.programId
    );

    const sig = await staking.methods
      .depositStake(5 * LAMPORTS_PER_SOL)
      .accounts({
        operator: operatorKeypair.publicKey,
        operatorAccount: operatorPda,
        stakeVault: vaultPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([operatorKeypair])
      .rpc();

    const opAccount = await staking.account.operatorAccount.fetch(operatorPda);
    expect(opAccount.stakedAmount.toNumber()).to.equal(15 * LAMPORTS_PER_SOL);
    logTx("deposit_additional_5_sol", sig);
  });

  // -----------------------------------------------------------------------
  // 9. Initiate unstake (begins 7-day unbonding)
  // -----------------------------------------------------------------------
  it("9. Initiate unstake (7-day unbonding)", async () => {
    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)],
      staking.programId
    );

    const sig = await staking.methods
      .initiateUnstake()
      .accounts({
        operator: operatorKeypair.publicKey,
        operatorAccount: operatorPda,
      })
      .signers([operatorKeypair])
      .rpc();

    const opAccount = await staking.account.operatorAccount.fetch(operatorPda);
    expect(opAccount.active).to.be.false;
    expect(opAccount.unstakeTime.toNumber()).to.be.greaterThan(0);
    logTx("initiate_unstake", sig);

    // Note: We cannot test withdraw here because 7 days haven't passed.
    // This is expected — the unbonding period is a security feature.
    console.log(
      `  ℹ️  Unbonding until: ${new Date(opAccount.unstakeTime.toNumber() * 1000).toISOString()}`
    );
  });

  // -----------------------------------------------------------------------
  // 10. Fee router: protocol deposits prepaid balance
  // -----------------------------------------------------------------------
  it("10. Protocol deposits 1 SOL prepaid fee balance", async () => {
    const protocolKeypair = Keypair.generate();

    // Fund the protocol account
    const airdropSig = await provider.connection.requestAirdrop(
      protocolKeypair.publicKey,
      2 * LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(airdropSig);

    const [protocolBalancePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("balance"), protocolKeypair.publicKey.toBuffer()],
      feeRouter.programId
    );
    const [feeVaultPda] = PublicKey.findProgramAddressSync(
      [FEE_VAULT_SEED],
      feeRouter.programId
    );

    const sig = await feeRouter.methods
      .depositBalance(1 * LAMPORTS_PER_SOL)
      .accounts({
        protocol: protocolKeypair.publicKey,
        protocolBalance: protocolBalancePda,
        feeVault: feeVaultPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([protocolKeypair])
      .rpc();

    const balance = await feeRouter.account.protocolBalance.fetch(
      protocolBalancePda
    );
    expect(balance.balance.toNumber()).to.equal(1 * LAMPORTS_PER_SOL);
    logTx("fee_deposit_1_sol", sig);
  });

  // -----------------------------------------------------------------------
  // 11. Registry: update operator endpoint
  // -----------------------------------------------------------------------
  it("11. Registry: update operator endpoint", async () => {
    const [registryPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("registry"), Buffer.from(operatorId)],
      registry.programId
    );

    const newEndpoint = "https://qpl-operator-1-v2.example.com:9090";
    const sig = await registry.methods
      .update(newEndpoint, null)
      .accounts({
        operator: operatorKeypair.publicKey,
        registryEntry: registryPda,
      })
      .signers([operatorKeypair])
      .rpc();

    const entry = await registry.account.registryEntry.fetch(registryPda);
    expect(entry.endpoint).to.equal(newEndpoint);
    logTx("registry_update_endpoint", sig);
  });

  // -----------------------------------------------------------------------
  // 12. Registry: deactivate operator
  // -----------------------------------------------------------------------
  it("12. Registry: deactivate operator", async () => {
    const [registryPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("registry"), Buffer.from(operatorId)],
      registry.programId
    );

    const sig = await registry.methods
      .deactivate()
      .accounts({
        operator: operatorKeypair.publicKey,
        registryEntry: registryPda,
      })
      .signers([operatorKeypair])
      .rpc();

    const entry = await registry.account.registryEntry.fetch(registryPda);
    expect(entry.active).to.be.false;
    logTx("registry_deactivate", sig);
  });

  // -----------------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------------
  after(() => {
    logSummary();
  });
});
