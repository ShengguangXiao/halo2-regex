use std::{
    fs::File,
    path::{Path, PathBuf},
    io::Read
};

use clap::{Parser, Subcommand};
use halo2_base::halo2_proofs::{
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    halo2curves::bn256::{Bn256, Fr, G1Affine, G1},
    plonk::{Any, Circuit},
};
use halo2_regex::helpers::*;
use halo2_regex::vrm::*;
use itertools::Itertools;
use std::marker::PhantomData;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    /// Generate a setup parameter (not for production).
    GenParams {
        /// k parameter for the one regex verification circuit.
        #[arg(long)]
        k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
    },
    /// Generate proving keys and verifying keys.
    GenKeys {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// regex lookup path
        #[arg(short, long, default_value = "./test_regexes/regex3_test_lookup.txt")]
        allstr_file_path: String,
        /// regex substr lookup file apth
        #[arg(short, long, default_value = "./test_regexes/substr3_test_lookup.txt")]
        substr_file_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        pk_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/app.vk")]
        vk_path: String,
    },
    Prove {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// regex lookup path
        #[arg(short, long, default_value = "./test_regexes/regex3_test_lookup.txt")]
        allstr_file_path: String,
        /// regex substr lookup file apth
        #[arg(short, long, default_value = "./test_regexes/substr3_test_lookup.txt")]
        substr_file_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        pk_path: String,
        /// the string to verify
        #[arg(short, long, default_value = "")]
        string_to_verify: String,
        /// the match target pos
        #[arg(long)]
        target_pos: u32,
        /// the match target string
        #[arg(short, long, default_value = "")]
        target_string: String,
        /// the regex match pass or not
        #[arg(long)]
        is_success: bool,
        /// output proof file
        #[arg(long, default_value = "./build/app.proof")]
        proof_path: String,
    },
    Verify {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// regex lookup path
        #[arg(short, long, default_value = "./test_regexes/regex3_test_lookup.txt")]
        allstr_file_path: String,
        /// regex substr lookup file apth
        #[arg(short, long, default_value = "./test_regexes/substr3_test_lookup.txt")]
        substr_file_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/app.vk")]
        vk_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/app.proof")]
        proof_path: String,
    },
    GenHalo2Texts {
        #[arg(short, long)]
        decomposed_regex_path: String,
        #[arg(short, long)]
        allstr_file_path: String,
        #[arg(short, long)]
        substrs_dir_path: String,
    },
    GenCircom {
        #[arg(short, long)]
        decomposed_regex_path: String,
        #[arg(short, long)]
        circom_file_path: String,
        #[arg(short, long)]
        template_name: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenParams { k, params_path } => gen_params(&params_path, k).unwrap(),
        Commands::GenKeys {
            params_path,
            allstr_file_path,
            substr_file_path,
            pk_path,
            vk_path,
        } => {
            set_config_params(allstr_file_path, substr_file_path);

            let circuit = RegexCircuit::<Fr> {
                characters: vec![],
                correct_substrs: vec![],
                is_success: false,
                _marker: PhantomData,
            };
            gen_keys(&params_path, &pk_path, &vk_path, circuit).expect("key generation failed");
        }
        Commands::Prove {
            params_path,
            allstr_file_path,
            substr_file_path,
            pk_path,
            string_to_verify,
            target_pos,
            target_string,
            is_success,
            proof_path,
        } => {
            set_config_params(allstr_file_path, substr_file_path);
            // println!("Before replace {:?}", string_to_verify);
            let mut string_to_verify_fix = string_to_verify.replace("\\r", "\r");
            string_to_verify_fix = string_to_verify_fix.replace("\\n", "\n");
            // println!("After replace {:?}", string_to_verify_fix);
            let characters: Vec<u8> = string_to_verify_fix.bytes().collect();
            let circuit = RegexCircuit::<Fr> {
                characters,
                correct_substrs: vec![(target_pos as usize, target_string)],
                is_success: is_success,
                _marker: PhantomData,
            };
            prove(&params_path, &pk_path, is_success, &proof_path, circuit).unwrap();
            println!("proof generated");
        }
        Commands::Verify {
            params_path,
            allstr_file_path,
            substr_file_path,
            vk_path,
            proof_path,
        } => {
            set_config_params(allstr_file_path, substr_file_path);
            let circuit = RegexCircuit::<Fr> {
                characters: vec![],
                correct_substrs: vec![],
                is_success: false,
                _marker: PhantomData,
            };
            let result = verify(&params_path, &vk_path, &proof_path, circuit);
            if result {
                println!("proof is valid");
            } else {
                println!("proof is invalid");
            }
        }
        Commands::GenHalo2Texts {
            decomposed_regex_path,
            allstr_file_path,
            substrs_dir_path,
        } => {
            let regex_decomposed: DecomposedRegexConfig =
                serde_json::from_reader(File::open(decomposed_regex_path).unwrap()).unwrap();
            let num_public_part = regex_decomposed
                .parts
                .iter()
                .filter(|part| part.is_public)
                .collect_vec()
                .len();
            let substr_file_pathes = (0..num_public_part)
                .map(|idx| {
                    PathBuf::new()
                        .join(&substrs_dir_path)
                        .join(&format!("substr{}.txt", idx))
                })
                .collect_vec();
            regex_decomposed
                .gen_regex_files(
                    &Path::new(&allstr_file_path).to_path_buf(),
                    &substr_file_pathes,
                )
                .unwrap();
        }
        Commands::GenCircom {
            decomposed_regex_path,
            circom_file_path,
            template_name,
        } => {
            let regex_decomposed: DecomposedRegexConfig =
                serde_json::from_reader(File::open(decomposed_regex_path).unwrap()).unwrap();
            let circom_path = PathBuf::from(circom_file_path);
            regex_decomposed
                .gen_circom(&circom_path, &template_name)
                .unwrap();
        }
    }
}
