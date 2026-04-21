use snarkblock::ark_serialize::CanonicalSerialize;
use snarkblock::test_util::test_rng;
use snarkblock::{chunk_setup, issuance_and_wf_setup};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(default)
}

fn print_size(label: &str, bytes: usize) {
    let mib = (bytes as f64) / (1000.0 * 1000.0);
    println!("{label}: {bytes} bytes ({mib:.2} MB)");
}

fn main() {
    let num_pubkeys = env_usize("SNARKBLOCK_NUM_PUBKEYS", 1);
    let head_chunk_size = env_usize("SNARKBLOCK_HEAD_CHUNK_SIZE", 1024);

    let mut rng = test_rng();

    let (iwf_pk, iwf_vk) = issuance_and_wf_setup(&mut rng, num_pubkeys);
    let (chunk_pk, chunk_vk) = chunk_setup(&mut rng, head_chunk_size);

    let iwf_pk_size = iwf_pk.uncompressed_size();
    let iwf_vk_size = iwf_vk.uncompressed_size();
    let chunk_pk_size = chunk_pk.uncompressed_size();
    let chunk_vk_size = chunk_vk.uncompressed_size();

    let total_pk_size = iwf_pk_size + chunk_pk_size;
    let total_vk_size = iwf_vk_size + chunk_vk_size;

    println!(
        "snarkblock uncompressed key-size benchmark (num_pubkeys={num_pubkeys}, head_chunk_size={head_chunk_size})"
    );

    print_size("issuance_and_wf.pk.binary", iwf_pk_size);
    print_size("issuance_and_wf.vk.binary", iwf_vk_size);
    print_size("chunk.pk.binary", chunk_pk_size);
    print_size("chunk.vk.binary", chunk_vk_size);

    print_size("total.pk.binary", total_pk_size);
    print_size("total.vk.binary", total_vk_size);
    print_size("total.pk+vk.binary", total_pk_size + total_vk_size);
}
