import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { QplStaking } from "../target/types/qpl_staking";
import { expect } from "chai";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";

describe("qpl-staking", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.QplStaking as Program<QplStaking>;
  const governance = provider.wallet;
  const treasury = provider.wallet.publicKey;

  // PDA seeds
  const CONFIG_SEED = Buffer.from("staking-config");
  const VAULT_SEED = Buffer.from("stake-vault");

  it("Initializes staking config", async () => {
    const [configPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [CONFIG_SEED],
      program.programId
    );

    await program.methods
      .initializeConfig(treasury)
      .accounts({
        config: configPda,
        governance: governance.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const config = await program.account.stakingConfig.fetch(configPda);
    expect(config.governance.toBase58()).to.equal(governance.publicKey.toBase58());
    expect(config.treasury.toBase58()).to.equal(treasury.toBase58());
  });

  it("Initializes stake vault", async () => {
    const [vaultPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      program.programId
    );

    await program.methods
      .initializeVault()
      .accounts({
        stakeVault: vaultPda,
        authority: governance.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const vault = await program.account.stakeVault.fetch(vaultPda);
    expect(vault.bump).to.be.a("number");
  });

  it("Rejects stake below minimum (1 SOL)", async () => {
    const operator = anchor.web3.Keypair.generate();
    const operatorId = new Uint8Array(32).fill(1);

    // Airdrop some SOL for tx fees (but not enough to stake)
    const sig = await provider.connection.requestAirdrop(
      operator.publicKey,
      0.1 * LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);

    const [operatorPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), operator.publicKey.toBuffer()],
      program.programId
    );

    const [vaultPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      program.programId
    );

    try {
      await program.methods
        .stake(operatorId, "http://localhost:9000", 0x02, 500_000_000) // 0.5 SOL < 1 SOL min
        .accounts({
          operator: operator.publicKey,
          operatorAccount: operatorPda,
          stakeVault: vaultPda,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([operator])
        .rpc();
      expect.fail("Should have rejected insufficient stake");
    } catch (err: any) {
      expect(err.error.errorCode.code).to.equal("InsufficientStake");
    }
  });

  it("Stakes 1 SOL successfully", async () => {
    const operator = anchor.web3.Keypair.generate();
    const operatorId = new Uint8Array(32).fill(2);

    // Airdrop 2 SOL
    const sig = await provider.connection.requestAirdrop(
      operator.publicKey,
      2 * LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);

    const [operatorPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), operator.publicKey.toBuffer()],
      program.programId
    );

    const [vaultPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      program.programId
    );

    await program.methods
      .stake(operatorId, "http://localhost:9000", 0x02, LAMPORTS_PER_SOL)
      .accounts({
        operator: operator.publicKey,
        operatorAccount: operatorPda,
        stakeVault: vaultPda,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([operator])
      .rpc();

    const opAccount = await program.account.operatorAccount.fetch(operatorPda);
    expect(opAccount.stakedAmount.toNumber()).to.equal(LAMPORTS_PER_SOL);
    expect(opAccount.active).to.be.true;
    expect(opAccount.endpoint).to.equal("http://localhost:9000");
  });
});
