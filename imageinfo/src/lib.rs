use anyhow::{Context, Result};
use base64::engine::{general_purpose, Engine as _};
use rand::{thread_rng, RngCore};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::{collections::HashMap, fs};

use image_rs::pull::PullClient;
use oci_distribution::secrets::RegistryAuth;
use sev::certs::snp::ecdsa::Signature;
use sev::firmware::{
    guest::{AttestationReport, Firmware},
    host::{CertTableEntry, CertType, TcbVersion},
};
use sevsnp::{
    serialize_report,
    sevsnp::{Attestation, CertificateChain, Report, SevProduct},
};

#[derive(Debug, Serialize, Deserialize)]
struct RequestData {
    image: String,
    digest: String,
    hw_attest: String,
}

pub async fn send_image(image: &str) -> Result<String> {
    let reference: oci_distribution::Reference = image.parse().unwrap();
    let auth = RegistryAuth::Anonymous;
    let path = PathBuf::new();
    let mut reg_client = PullClient::new(reference.clone(), &path, &auth, 1).unwrap();
    let (_, digest, _) = reg_client.pull_manifest().await.unwrap();

    let ok = read_cmdline(&reference.to_string(), &digest.to_string()).await?;
    Ok(ok)
}

pub async fn read_cmdline(image: &str, digest: &str) -> Result<String> {
    let client = Client::new();
    let b64_value = base64_encode_report(&get_report().unwrap()).unwrap();

    let req_data = RequestData {
        image: String::from(image),
        digest: String::from(digest),
        hw_attest: b64_value,
    };

    let json_data = serde_json::to_string(&req_data)?;

    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let mut cmd_map: HashMap<String, String> = HashMap::new();

    for entry in cmdline.split_whitespace() {
        if let Some((key, value)) = entry.split_once('=') {
            cmd_map.insert(key.to_string(), value.to_string());
        } else {
            cmd_map.insert(entry.to_string(), String::new());
        }
    }

    let key = "sylabs.attest_server";
    if let Some(value) = cmd_map.get(key) {
        let url = format!("{}/endpoint", value);
        let _ = client.post(url).body(json_data).send().await;
    }

    Ok("done".to_string())
}

struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
}

fn extract_tcb_version(tcb_version: &TcbVersion) -> u64 {
    (tcb_version.microcode as u64) << 56
        | (tcb_version.snp as u64) << 48
        | (tcb_version.tee as u64) << 8
        | (tcb_version.bootloader as u64)
}

// serialize signature to bytes
fn signature_to_bytes(signature: &Signature) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    let b: Vec<u8> = signature
        .r()
        .iter()
        .chain(signature.s().iter())
        .cloned()
        .collect();

    let _ = buf.write(&b);

    let mut padding: Vec<u8> = vec![0; 512 - b.len()];

    buf.append(&mut padding);

    buf
}

fn get_report() -> Result<Attestation> {
    let vmpl = Some(0);
    let data = Some(create_random_request());

    let snp_evidence = match request_hardware_report(data, vmpl) {
        Ok(value) => value,
        Err(_) => panic!("not working"),
    };

    let mut attestation = Attestation::default();

    attestation.report = Some(Report {
        family_id: snp_evidence.attestation_report.family_id.to_vec(),
        report_data: snp_evidence.attestation_report.report_data.to_vec(),
        measurement: snp_evidence.attestation_report.measurement.to_vec(),
        guest_svn: snp_evidence.attestation_report.guest_svn,
        policy: snp_evidence.attestation_report.policy.0,
        image_id: snp_evidence.attestation_report.image_id.to_vec(),
        vmpl: snp_evidence.attestation_report.vmpl,
        signature_algo: snp_evidence.attestation_report.sig_algo,
        current_tcb: extract_tcb_version(&snp_evidence.attestation_report.current_tcb),
        platform_info: snp_evidence.attestation_report.plat_info.0,
        signer_info: 0,
        host_data: snp_evidence.attestation_report.host_data.to_vec(),
        id_key_digest: snp_evidence.attestation_report.id_key_digest.to_vec(),
        version: snp_evidence.attestation_report.version,
        author_key_digest: snp_evidence.attestation_report.author_key_digest.to_vec(),
        report_id: snp_evidence.attestation_report.report_id.to_vec(),
        report_id_ma: snp_evidence.attestation_report.report_id_ma.to_vec(),
        reported_tcb: extract_tcb_version(&snp_evidence.attestation_report.reported_tcb),
        chip_id: snp_evidence.attestation_report.chip_id.to_vec(),
        committed_tcb: extract_tcb_version(&snp_evidence.attestation_report.committed_tcb),
        current_build: u32::from(snp_evidence.attestation_report.current_build),
        current_minor: u32::from(snp_evidence.attestation_report.current_minor),
        current_major: u32::from(snp_evidence.attestation_report.current_major),
        committed_build: u32::from(snp_evidence.attestation_report.committed_build),
        committed_minor: u32::from(snp_evidence.attestation_report.committed_minor),
        committed_major: u32::from(snp_evidence.attestation_report.committed_major),
        launch_tcb: extract_tcb_version(&snp_evidence.attestation_report.launch_tcb),
        signature: signature_to_bytes(&snp_evidence.attestation_report.signature),
    });

    // println!("{:0x}", snp_evidence.attestation_report.version);

    let mut certificate_chain = CertificateChain::default();

    match snp_evidence.cert_chain {
        Some(v) => {
            for cert in v.iter() {
                match cert.cert_type {
                    CertType::ARK => {
                        certificate_chain.ark_cert = cert.data().to_vec();
                    }
                    CertType::CRL => {}
                    CertType::ASK => {
                        certificate_chain.ask_cert = cert.data().to_vec();
                    }
                    CertType::Empty => {}
                    CertType::VCEK => {
                        certificate_chain.vcek_cert = cert.data().to_vec();
                    }
                    CertType::VLEK => {
                        certificate_chain.vlek_cert = cert.data().to_vec();
                    }
                    CertType::OTHER(_) => {}
                };
            }
        }
        None => {}
    };

    attestation.certificate_chain = Some(certificate_chain);

    let mut sev_product = SevProduct::default();

    // TODO: get these values from somewhere
    sev_product.name = 1; // MILAN
    sev_product.stepping = 0;
    // prod.machine_stepping = Some(121 as u32);

    attestation.product = Some(sev_product);

    Ok(attestation)
}

fn base64_encode_report(attestation: &Attestation) -> Result<String> {
    let b = serialize_report(attestation);
    let mut buf = String::new();
    general_purpose::STANDARD.encode_string(b, &mut buf);
    Ok(String::from(buf))
}

// Create 64 random bytes of data for attestation report request
pub fn create_random_request() -> [u8; 64] {
    let mut data = [0u8; 64];
    thread_rng().fill_bytes(&mut data);
    data
}

fn request_hardware_report(data: Option<[u8; 64]>, vmpl: Option<u32>) -> Result<SnpEvidence> {
    let mut fw = Firmware::open().context("unable to open /dev/sev-guest")?;

    let (report, certs) = fw
        .get_ext_report(None, data, vmpl)
        .context("Failed to get attestation report")?;

    Ok(SnpEvidence {
        attestation_report: report,
        cert_chain: certs,
    })
}
