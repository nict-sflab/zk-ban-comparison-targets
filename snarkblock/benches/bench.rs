use criterion::{criterion_group, criterion_main, Criterion};
use rayon::prelude::*;
use snarkblock::test_util::{rand_issuance, test_rng};
use snarkblock::{
    agg_chunk_setup, agg_iwf_setup, chunk_setup, issuance_and_wf_setup, AggChunkProver,
    AggChunkVerifier, AggIwfProver, AggIwfVerifier, BlocklistCom, Chunk, ChunkPreparer, ChunkProof,
    ChunkProver, IssuanceAndWfProver, PreparedChunk, PrivateId, SnarkblockProof,
    SnarkblockVerifier,
};

const SYNC_NUM_CHUNKS: usize = 30;
const SYNC_CHUNK_SIZE: usize = 1024;

const AUTH_NUM_PUBKEYS: usize = 1;
const AUTH_NUM_HEAD_CHUNKS: usize = 254;
const AUTH_HEAD_CHUNK_SIZE: usize = 32768;

fn bench_sync(c: &mut Criterion) {
    let mut rng = test_rng();
    let priv_id = PrivateId::gen(&mut rng);
    let chunk = Chunk::gen_with_size(&mut rng, SYNC_CHUNK_SIZE);
    let (chunk_pk, _) = chunk_setup(&mut rng, SYNC_CHUNK_SIZE);
    let chunk_prover = ChunkProver {
        priv_id,
        proving_key: chunk_pk,
    };

    c.bench_function(
        &format!(
            "Sync cost: prove {} chunks in parallel [cs={}]",
            SYNC_NUM_CHUNKS, SYNC_CHUNK_SIZE
        ),
        |b| {
            b.iter(|| {
                (0..SYNC_NUM_CHUNKS).into_par_iter().for_each(|_| {
                    let mut thread_rng = test_rng();
                    chunk_prover
                        .prove(&mut thread_rng, &chunk)
                        .expect("couldn't prove chunk");
                })
            })
        },
    );
}

fn bench_auth(c: &mut Criterion) {
    let mut rng = test_rng();

    let priv_id = PrivateId::gen(&mut rng);
    let blocklist_elem = priv_id.gen_blocklist_elem(&mut rng);
    let (pubkeys, signers_pubkey_idx, sig, priv_id_opening) =
        rand_issuance(&mut rng, priv_id, AUTH_NUM_PUBKEYS);

    let blocklist_head_chunk = Chunk::gen_with_size(&mut rng, AUTH_HEAD_CHUNK_SIZE);

    let (iwf_pk, iwf_vk) = issuance_and_wf_setup(&mut rng, AUTH_NUM_PUBKEYS);
    let (agg_iwf_pk, agg_iwf_vk) = agg_iwf_setup(&mut rng);
    let (head_chunk_pk, head_chunk_vk) = chunk_setup(&mut rng, AUTH_HEAD_CHUNK_SIZE);
    let (agg_head_chunk_pk, agg_head_chunk_vk) = agg_chunk_setup(&mut rng, AUTH_NUM_HEAD_CHUNKS);

    let iwf_prover = IssuanceAndWfProver {
        priv_id,
        pubkeys: pubkeys.clone(),
        signers_pubkey_idx,
        priv_id_opening,
        sig,
        proving_key: iwf_pk,
    };
    let agg_iwf_prover = AggIwfProver {
        priv_id,
        circuit_verif_key: iwf_vk.clone(),
        agg_proving_key: agg_iwf_pk,
    };
    let agg_iwf_verifier = AggIwfVerifier {
        pubkeys,
        circuit_verif_key: iwf_vk,
        agg_verif_key: agg_iwf_vk,
    };
    let head_chunk_prover = ChunkProver {
        priv_id,
        proving_key: head_chunk_pk,
    };
    let head_chunk_preparer = ChunkPreparer {
        verif_key: head_chunk_vk.clone(),
    };
    let agg_head_chunk_prover = AggChunkProver {
        priv_id,
        circuit_verif_key: head_chunk_vk.clone(),
        agg_proving_key: agg_head_chunk_pk.clone(),
    };
    let agg_head_chunk_verifier = AggChunkVerifier {
        circuit_verif_key: head_chunk_vk,
        agg_verif_key: agg_head_chunk_vk,
    };
    let snarkblock_verifier = SnarkblockVerifier {
        agg_chunk_verifiers: vec![agg_head_chunk_verifier],
        agg_iwf_verifier,
    };

    let prepared_head_chunk = head_chunk_preparer
        .prepare(&blocklist_head_chunk)
        .expect("couldn't prepare chunk");
    let prepared_head_chunks_template: Vec<PreparedChunk> =
        vec![prepared_head_chunk; AUTH_NUM_HEAD_CHUNKS];
    let head_chunk_proof = head_chunk_prover
        .prove(&mut rng, &blocklist_head_chunk)
        .expect("couldn't prove chunk");
    let head_chunk_proofs_template: Vec<ChunkProof> =
        vec![head_chunk_proof; AUTH_NUM_HEAD_CHUNKS];

    let mut prepared_for_com = prepared_head_chunks_template.clone();
    let blocklist_head_com =
        BlocklistCom::from_prepared_chunks(&mut prepared_for_com, &agg_head_chunk_pk);

    c.bench_function(
        &format!(
            "Authentication prover latency [offline-chunks,nc={},cs={},np={}]",
            AUTH_NUM_HEAD_CHUNKS, AUTH_HEAD_CHUNK_SIZE, AUTH_NUM_PUBKEYS
        ),
        |b| {
            b.iter(|| {
                let agg_iwf_proof = {
                    let base_iwf_proof = iwf_prover
                        .prove(&mut rng, blocklist_elem)
                        .expect("couldn't prove base IWF");
                    agg_iwf_prover
                        .prove(&mut rng, &base_iwf_proof)
                        .expect("couldn't prove IWF HiCIAP")
                };

                let mut head_chunk_proofs = head_chunk_proofs_template.clone();
                let mut prepared_head_chunks = prepared_head_chunks_template.clone();

                let agg_head_chunk_proof = agg_head_chunk_prover
                    .prove(
                        &mut rng,
                        &mut head_chunk_proofs,
                        &mut prepared_head_chunks,
                    )
                    .expect("couldn't prove HiCIAP over head chunks");

                let _snarkblock_proof =
                    SnarkblockProof::new(&mut rng, agg_iwf_proof, vec![agg_head_chunk_proof]);
            })
        },
    );

    let mut initial_head_chunk_proofs = head_chunk_proofs_template.clone();
    let mut prepared_for_proof = prepared_head_chunks_template.clone();
    let agg_head_chunk_proof = agg_head_chunk_prover
        .prove(
            &mut rng,
            &mut initial_head_chunk_proofs,
            &mut prepared_for_proof,
        )
        .expect("couldn't prove HiCIAP over head chunks");
    let agg_iwf_proof = {
        let base_iwf_proof = iwf_prover
            .prove(&mut rng, blocklist_elem)
            .expect("couldn't prove base IWF");
        agg_iwf_prover
            .prove(&mut rng, &base_iwf_proof)
            .expect("couldn't prove IWF HiCIAP")
    };
    let unbuffered_snarkblock_proof =
        SnarkblockProof::new(&mut rng, agg_iwf_proof, vec![agg_head_chunk_proof]);

    c.bench_function(
        &format!(
            "Authentication verifier latency [nobuf,nc={},cs={},np={}]",
            AUTH_NUM_HEAD_CHUNKS, AUTH_HEAD_CHUNK_SIZE, AUTH_NUM_PUBKEYS
        ),
        |b| {
            b.iter(|| {
                assert!(snarkblock_verifier
                    .verify(
                        vec![blocklist_head_com.clone()],
                        &blocklist_elem,
                        unbuffered_snarkblock_proof.clone(),
                    )
                    .unwrap());
            })
        },
    );
}

criterion_group!(benches, bench_auth, bench_sync);
criterion_main!(benches);
