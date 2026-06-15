/**
 * QPL Warp-Time Tests — Phase 2
 * =============================================================================
 *
 * These tests run AFTER Phase 1 has set up state (initiated unstake + slash)
 * and the validator has been restarted with --warp-slot to jump forward.
 *
 * Phase 1: extended-test.ts (tests A-D, G1-G4, plus setup)
 * Phase 2: warp-test.ts (tests E-F: execute slash + withdraw after unbonding)
 *
 * Usage (run the orchestrator script):
 *   bash tests/solana/run-warp-tests.sh
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { QplStaking } from "../target/types/qpl_staking";
import {
  LAMPORTS_PER_SOL,
  PublicKey,
} from "@solana/web3.js";
import BN from "bn.js";
import { expect } from "chai";
import * as fs from "fs";

const TX_RESULTS: { name: string; sig: string }[] = [];

function logTx(name: string, sig: string) {
  TX_RESULTS.push({ name, sig });
  console.log(`  ✅ ${name}: ${sig}`);
}

describe("QPL Warp-Time Tests", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const staking = anchor.workspace.QplStaking as Program<QplStaking>;
  const authority = (provider.wallet as anchor.Wallet).payer;
  const treasury = authority.publicKey;

  const VAULT_SEED = Buffer.from("vault");
  const CONFIG_SEED = Buffer.from("config");

  // Must match the operator from phase 1 setup
  // Read operatorId from the state file written by phase 1
  const stateFile = "/tmp/qpl-warp-state.json";
  let operatorId: Uint8Array;
  let operatorPubkey: PublicKey;

  before(async () => {
    // Read state from phase 1
    if (fs.existsSync(stateFile)) {
      const state = JSON.parse(fs.readFileSync(stateFile, "utf-8"));
      operatorId = new Uint8Array(JSON.parse(state.operatorId));
      operatorPubkey = new PublicKey(state.operatorPubkey);
      console.log(`  ℹ️  Phase 1 state: operator ${operatorPubkey.toBase58()}`);
    } else {
      throw new Error(`State file ${stateFile} not found. Run phase 1 first.`);
    }
  });

  // =========================================================================
  // E. EXECUTE SLASH AFTER DISPUTE WINDOW
  // =========================================================================
  it("E. Execute pending slash (dispute window elapsed)", async () => {
    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)], staking.programId
    );
    const [configPda] = PublicKey.findProgramAddressSync(
      [CONFIG_SEED], staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED], staking.programId
    );

    // Verify pending slash exists from phase 1
    const opBefore = await staking.account.operatorAccount.fetch(operatorPda);
    const pendingSlash = opBefore.pendingSlashAmount.toNumber();
    console.log(`  ℹ️  Pending slash: ${pendingSlash / LAMPORTS_PER_SOL} SOL`);
    expect(pendingSlash).to.be.greaterThan(0);

    const sig = await staking.methods.executeSlash()
      .accounts({
        executor: authority.publicKey,
        operatorAccount: operatorPda,
        stakeVault: vaultPda,
        treasury: treasury,
        config: configPda,
      })
      .rpc();

    const opAfter = await staking.account.operatorAccount.fetch(operatorPda);
    expect(opAfter.pendingSlashAmount.toNumber()).to.equal(0);
    expect(opAfter.stakedAmount.toNumber()).to.equal(
      opBefore.stakedAmount.toNumber() - pendingSlash
    );

    logTx("execute_slash_after_dispute", sig);
    console.log(`  ℹ️  Slashed ${pendingSlash / LAMPORTS_PER_SOL} SOL, remaining: ${opAfter.stakedAmount.toNumber() / LAMPORTS_PER_SOL} SOL`);
  });

  // =========================================================================
  // F. WITHDRAW STAKE AFTER UNBONDING PERIOD
  // =========================================================================
  it("F. Withdraw stake after unbonding period", async () => {
    const [operatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), Buffer.from(operatorId)], staking.programId
    );
    const [vaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED], staking.programId
    );

    const opBefore = await staking.account.operatorAccount.fetch(operatorPda);
    expect(opBefore.unstakeTime.toNumber()).to.be.greaterThan(0);
    expect(opBefore.active).to.be.false;

    const stakedAmount = opBefore.stakedAmount.toNumber();
    const balanceBefore = await provider.connection.getBalance(operatorPubkey);

    const sig = await staking.methods.withdraw()
      .accounts({
        operator: operatorPubkey,
        operatorAccount: operatorPda,
        stakeVault: vaultPda,
      })
      .rpc();

    const opAfter = await staking.account.operatorAccount.fetch(operatorPda);
    expect(opAfter.stakedAmount.toNumber()).to.equal(0);

    const balanceAfter = await provider.connection.getBalance(operatorPubkey);
    expect(balanceAfter).to.be.greaterThan(balanceBefore);

    logTx("withdraw_after_unbonding", sig);
    console.log(`  ℹ️  Withdrawn: ${stakedAmount / LAMPORTS_PER_SOL} SOL`);
  });

  // =========================================================================
  // SUMMARY
  // =========================================================================
  after(() => {
    console.log("\n" + "=".repeat(70));
    console.log("  QPL WARP-TIME TESTS — RESULTS");
    console.log("=".repeat(70));
    console.log(`  Transactions: ${TX_RESULTS.length}`);
    console.log("-".repeat(70));
    for (const tx of TX_RESULTS) {
      console.log(`  ${tx.name.padEnd(35)} ${tx.sig}`);
    }
    console.log("=".repeat(70));
  });
});
