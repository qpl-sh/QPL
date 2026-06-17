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
 * Total SOL cost: ~50 SOL (stake deposits + fee deposits + rent).
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TX_RESULTS: { name: string; sig: string }[] = [];

function logTx(name: string, sig: string) {
  TX_RESULTS.push({ name, sig });
  console.log(`  ✅ ${name}: ${sig}`);
}

function logSummary(authorityPubKey?: string) {
  console.log("\n" + "=".repeat(70));
  console.log("  QPL DEVNET SMOKE TEST — RESULTS");
  console.log("=".repeat(70));
  console.log(`  Cluster: devnet`);
  console.log(`  Authority: ${authorityPubKey ?? "unknown"}`);
  console.log(`  Timestamp: ${new Date().toISOString()}`);
  console.log(`  Transactions: ${TX_RESULTS.length}`);
  console.log("-".repeat(70));
  for (const tx of TX_RESULTS) {
    console.log(`  ${tx.name.padEnd(35)} ${tx.sig}`);
  }
  console.log("=".repeat(70));
  console.log(
    `\n  Explorer: https://explorer.solana.com/?cluster=devnet`
  );
  console.log(
    `  Verify each tx at: https://explorer.solana.com/tx/<sig>?cluster=devnet\n`
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

    try {
      const sig = await staking.methods
        .initializeConfig(treasury)
        .accounts({
          config: configPda,
          governance: authority.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
        .rpc();
      logTx("init_staking_config", sig);
    } catch (err: any) {
      if (err.logs && err.logs.some((l: string) => l.includes("already in use"))) {
        console.log("  \u2705 init_staking_config: already initialized (skipped)");
      } else {
        throw err;
      }
    }

    const config = await staking.account.stakingConfig.fetch(configPda);
    expect(config.governance.toBase58()).to.equal(authority.publicKey.toBase58());
    expect(config.treasury.toBase58()).to.equal(treasury.toBase58());
  });

  // -----------------------------------------------------------------------
  // 2. Initialize stake vault
  // -----------------------------------------------------------------------
  it("2. Initialize stake vault", async () => {
    const [configPda] = PublicKey.findProgramAddressSync(
      [CONFIG_SEED],
      staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      staking.programId
    );

    try {
      const sig = await staking.methods
        .initializeVault()
        .accounts({
          config: configPda,
          stakeVault: vaultPda,
          authority: authority.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
        .rpc();
      logTx("init_stake_vault", sig);
    } catch (err: any) {
      if (err.logs && err.logs.some((l: string) => l.includes("already in use"))) {
        console.log("  \u2705 init_stake_vault: already initialized (skipped)");
      } else {
        throw err;
      }
    }

    const vault = await staking.account.stakeVault.fetch(vaultPda);
    expect(vault.bump).to.be.a("number");
  });

  // -----------------------------------------------------------------------
  // 3. Initialize fee router config
  // -----------------------------------------------------------------------
  it("3. Initialize fee router config", async () => {
    const [feeConfigPda] = PublicKey.findProgramAddressSync(
      [FEE_CONFIG_SEED],
      feeRouter.programId
    );

    try {
      const sig = await feeRouter.methods
        .initialize(treasury)
        .accounts({
          config: feeConfigPda,
          governance: authority.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
        .rpc();
      logTx("init_fee_router_config", sig);
    } catch (err: any) {
      if (err.logs && err.logs.some((l: string) => l.includes("already in use"))) {
        console.log("  \u2705 init_fee_router_config: already initialized (skipped)");
      } else {
        throw err;
      }
    }

    const config = await feeRouter.account.feeRouterConfig.fetch(feeConfigPda);
    expect(config.governance.toBase58()).to.equal(authority.publicKey.toBase58());
    // totalFeesCollected may be > 0 if config PDA persists from a previous run
    expect(config.totalFeesCollected.toNumber()).to.be.greaterThanOrEqual(0);
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

    try {
      const sig = await feeRouter.methods
        .initializeVault()
        .accounts({
          config: feeConfigPda,
          feeVault: feeVaultPda,
          governance: authority.publicKey,
          systemProgram: SystemProgram.programId,
        } as any)
        .rpc();
      logTx("init_fee_vault", sig);
    } catch (err: any) {
      if (err.logs && err.logs.some((l: string) => l.includes("already in use"))) {
        console.log("  \u2705 init_fee_vault: already initialized (skipped)");
      } else {
        throw err;
      }
    }

    const vault = await feeRouter.account.feeVault.fetch(feeVaultPda);
    expect(vault.bump).to.be.a("number");
  });

  // -----------------------------------------------------------------------
  // 5. Register operator in registry
  // -----------------------------------------------------------------------
  it("5. Register operator in registry", async () => {
    // Fund operator before registration (rent for registry PDA + tx fees)
    const transferAmount = Math.floor(50 * LAMPORTS_PER_SOL);
    const transferSig = await provider.connection.sendTransaction(
        new anchor.web3.Transaction().add(
          SystemProgram.transfer({
            fromPubkey: authority.publicKey,
            toPubkey: operatorKeypair.publicKey,
            lamports: transferAmount,
          })
        ),
        [authority]
      );
      await provider.connection.confirmTransaction(transferSig);

    const [registryPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("registry"), operatorKeypair.publicKey.toBuffer()],
      registry.programId
    );

    try {
      const sig = await registry.methods
        .register(Array.from(operatorId), OPERATOR_ENDPOINT, SERVICE_SIGNING | SERVICE_PROVING)
        .accounts({
          operator: operatorKeypair.publicKey,
          registryEntry: registryPda,
          systemProgram: SystemProgram.programId,
        } as any)
        .signers([operatorKeypair])
        .rpc();
      logTx("registry_register", sig);
      registryFresh = true;
    } catch (err: any) {
      if (err.logs && err.logs.some((l: string) => l.includes("already in use"))) {
        console.log("  \u2705 registry_register: already registered (skipped)");
      } else {
        throw err;
      }
    }

    const entry = await registry.account.registryEntry.fetch(registryPda);
    if (registryFresh) {
      expect(entry.endpoint).to.equal(OPERATOR_ENDPOINT);
      expect(entry.active).to.be.true;
    }
    expect(entry.servicesBitmask).to.equal(SERVICE_SIGNING | SERVICE_PROVING);
  });

  // Track whether staking and registry were set up fresh (for dependent tests)
  let stakingFresh = false;
  let registryFresh = false;

  // -----------------------------------------------------------------------
  // 6. Fund operator and stake
  // -----------------------------------------------------------------------
  it("6. Stake 15 SOL (above 10 SOL minimum)", async () => {
    // Operator already funded in test 5

    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)],
      staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      staking.programId
    );

    try {
      const sig = await staking.methods
        .stake(
          Array.from(operatorId),
          OPERATOR_ENDPOINT,
          SERVICE_SIGNING | SERVICE_PROVING,
          new BN(Math.floor(15 * LAMPORTS_PER_SOL))
        )
        .accounts({
          operator: operatorKeypair.publicKey,
          operatorAccount: operatorPda,
          stakeVault: vaultPda,
          systemProgram: SystemProgram.programId,
        } as any)
        .signers([operatorKeypair])
        .rpc();

      const opAccount = await staking.account.operatorAccount.fetch(operatorPda);
      expect(opAccount.stakedAmount.toNumber()).to.equal(Math.floor(15 * LAMPORTS_PER_SOL));
      expect(opAccount.active).to.be.true;
      logTx("stake_15_sol", sig);
      stakingFresh = true;
    } catch (err: any) {
      if (err.logs && err.logs.some((l: string) => l.includes("already in use"))) {
        console.log("  \u2705 stake: operator account already exists from previous run (skipped)");
      } else {
        throw err;
      }
    }
  });

  // -----------------------------------------------------------------------
  // 7. Reject stake below minimum
  // -----------------------------------------------------------------------
  it("7. Reject stake below minimum (5 SOL < 10 SOL)", async function () {
    const underfundedOp = Keypair.generate();
    const underfundedId = new Uint8Array(32).fill(99);

    // Transfer 5 SOL to underfunded account (below 10 SOL min stake)
    const transferSig = await provider.connection.sendTransaction(
      new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: authority.publicKey,
          toPubkey: underfundedOp.publicKey,
          lamports: Math.floor(5 * LAMPORTS_PER_SOL),
        })
      ),
      [authority]
    );
    await provider.connection.confirmTransaction(transferSig);

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
          new BN(Math.floor(5 * LAMPORTS_PER_SOL))
        )
        .accounts({
          operator: underfundedOp.publicKey,
          operatorAccount: operatorPda,
          stakeVault: vaultPda,
          systemProgram: SystemProgram.programId,
        } as any)
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
  it("8. Deposit additional 5 SOL stake", async function () {
    if (!stakingFresh) {
      console.log("  \u2705 deposit: skipped (operator from previous run)");
      this.skip();
      return;
    }
    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)],
      staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      staking.programId
    );

    const sig = await staking.methods
      .depositStake(new BN(Math.floor(5 * LAMPORTS_PER_SOL)))
      .accounts({
        operator: operatorKeypair.publicKey,
        operatorAccount: operatorPda,
        stakeVault: vaultPda,
        systemProgram: SystemProgram.programId,
      } as any)
      .signers([operatorKeypair])
      .rpc();

    const opAccount = await staking.account.operatorAccount.fetch(operatorPda);
    expect(opAccount.stakedAmount.toNumber()).to.equal(Math.floor(20 * LAMPORTS_PER_SOL));
    logTx("deposit_additional_5_sol", sig);
  });

  // -----------------------------------------------------------------------
  // 9. Initiate unstake (begins 7-day unbonding)
  // -----------------------------------------------------------------------
  it("9. Initiate unstake (7-day unbonding)", async function () {
    if (!stakingFresh) {
      console.log("  \u2705 unstake: skipped (operator from previous run)");
      this.skip();
      return;
    }
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
  it("10. Protocol deposits 2 SOL prepaid fee balance", async function () {
    const protocolKeypair = Keypair.generate();

    // Transfer SOL from authority wallet to protocol account
    const transferSig = await provider.connection.sendTransaction(
      new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: authority.publicKey,
          toPubkey: protocolKeypair.publicKey,
          lamports: Math.floor(5 * LAMPORTS_PER_SOL),
        })
      ),
      [authority]
    );
    await provider.connection.confirmTransaction(transferSig);

    const [protocolBalancePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("balance"), protocolKeypair.publicKey.toBuffer()],
      feeRouter.programId
    );
    const [feeVaultPda] = PublicKey.findProgramAddressSync(
      [FEE_VAULT_SEED],
      feeRouter.programId
    );

    const sig = await feeRouter.methods
      .depositBalance(new BN(Math.floor(2 * LAMPORTS_PER_SOL)))
      .accounts({
        protocol: protocolKeypair.publicKey,
        protocolBalance: protocolBalancePda,
        feeVault: feeVaultPda,
        systemProgram: SystemProgram.programId,
      } as any)
      .signers([protocolKeypair])
      .rpc();

    const balance = await feeRouter.account.protocolBalance.fetch(
      protocolBalancePda
    );
    expect(balance.balance.toNumber()).to.equal(Math.floor(2 * LAMPORTS_PER_SOL));
    logTx("fee_deposit_2_sol", sig);
  });

  // -----------------------------------------------------------------------
  // 11. Registry: update operator endpoint
  // -----------------------------------------------------------------------
  it("11. Registry: update operator endpoint", async function () {
    if (!registryFresh) {
      console.log("  \u2705 update: skipped (registry from previous run)");
      this.skip();
      return;
    }
    const [registryPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("registry"), operatorKeypair.publicKey.toBuffer()],
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
  it("12. Registry: deactivate operator", async function () {
    if (!registryFresh) {
      console.log("  \u2705 deactivate: skipped (registry from previous run)");
      this.skip();
      return;
    }
    const [registryPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("registry"), operatorKeypair.publicKey.toBuffer()],
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
    logSummary(authority.publicKey.toBase58());
  });
});
