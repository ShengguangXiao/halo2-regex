use crate::vrm::DecomposedRegexConfig;
use halo2_base::halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure};
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error, ProvingKey,
    VerifyingKey,
};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC, VerifierSHPLONK};
use halo2_base::halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::poly::VerificationStrategy;
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, fe_to_biguint, modulus, PrimeField},
    AssignedValue, Context, ContextParams, QuantumCell, SKIP_FIRST_PASS,
};

use itertools::Itertools;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;
use std::arch::x86_64::_CMP_TRUE_UQ;
use std::env::set_var;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Mutex;

use crate::defs::*;
use crate::RegexVerifyConfig;

const MAX_STRING_LEN: usize = 1024;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RegexVerifyConfigParams {
    /// The degree of the number of rows, i.e., 2^(`degree`) rows are set.
    pub k: usize,
    pub allstr_file_path: String,
    pub substr_file_path: String,
}

lazy_static! {
    static ref regexConfigParams: Mutex<RegexVerifyConfigParams> =
        Mutex::new(RegexVerifyConfigParams {
            k: 17,
            allstr_file_path: "".to_string(),
            substr_file_path: "".to_string(),
        });
}

pub fn set_config_params(allstr: String, substr: String) {
    let mut params = regexConfigParams.lock().unwrap();
    params.allstr_file_path = allstr;
    params.substr_file_path = substr;
}

pub fn set_config_k(_k: usize) {
    regexConfigParams.lock().unwrap().k = _k;
}

#[derive(Default, Clone, Debug)]
pub struct RegexCircuit<F: PrimeField> {
    pub characters: Vec<u8>,
    pub correct_substrs: Vec<(usize, String)>,
    pub is_success: bool,
    pub _marker: PhantomData<F>,
}

impl<F: PrimeField> RegexCircuit<F> {
    const NUM_ADVICE: usize = 25;
    const NUM_FIXED: usize = 1;
}

impl<F: PrimeField> Circuit<F> for RegexCircuit<F> {
    type Config = RegexVerifyConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    // Circuit without witnesses, called only during key generation
    fn without_witnesses(&self) -> Self {
        Self {
            characters: vec![],
            correct_substrs: vec![],
            is_success: false,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params = regexConfigParams.lock().unwrap();
        let all_regex_def = AllstrRegexDef::read_from_text(&params.allstr_file_path);
        let substr_def = SubstrRegexDef::read_from_text(&params.substr_file_path);
        let gate = FlexGateConfig::<F>::configure(
            meta,
            halo2_base::gates::flex_gate::GateStrategy::Vertical,
            &[Self::NUM_ADVICE],
            Self::NUM_FIXED,
            0,
            params.k,
        );
        let regex_defs = vec![RegexDefs {
            allstr: all_regex_def,
            substrs: vec![substr_def],
        }];
        let config = RegexVerifyConfig::configure(meta, MAX_STRING_LEN, gate, regex_defs);
        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load(&mut layouter)?;

        // println!("Synthesize being called...");
        let mut first_pass = SKIP_FIRST_PASS;
        let gate = config.gate().clone();

        layouter.assign_region(
            || "regex",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );
                let ctx = &mut aux;
                let result = config.match_substrs(ctx, &self.characters)?;
                let mut expected_masked_chars = vec![0; MAX_STRING_LEN];
                let mut expected_substr_ids = vec![0; MAX_STRING_LEN];

                if self.is_success {
                    for (substr_idx, (start, chars)) in self.correct_substrs.iter().enumerate() {
                        for (idx, char) in chars.as_bytes().iter().enumerate() {
                            expected_masked_chars[start + idx] = *char;
                            expected_substr_ids[start + idx] = substr_idx + 1;
                        }
                    }
                    for idx in 0..MAX_STRING_LEN {
                        result.masked_characters[idx]
                            .value()
                            .map(|v| assert_eq!(*v, F::from(expected_masked_chars[idx] as u64)));
                        result.all_substr_ids[idx]
                            .value()
                            .map(|v| assert_eq!(*v, F::from(expected_substr_ids[idx] as u64)));
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

// /// The number of limbs of the accumulator in the aggregation circuit.
// pub const NUM_ACC_INSTANCES: usize = 4 * LIMBS;
// /// The name of env variable for the path to the configuration json of the aggregation circuit.
// pub const VERIFY_CONFIG_KEY: &'static str = "VERIFY_CONFIG";

/// Generate SRS parameters.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `k` - the SRS size.
pub fn gen_params(params_path: &str, k: u32) -> Result<(), Error> {
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(k, rng);
    let f = File::create(params_path).unwrap();
    let mut writer = BufWriter::new(f);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();
    Ok(())
}

/// Generate proving and verifying keys for the regex verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `pk_path` - a file path of the output proving key.
/// * `vk_path` - a file path of the output verifying key.
/// * `circuit` - an regex verification circuit.
pub fn gen_keys<C: Circuit<Fr>>(
    params_path: &str,
    pk_path: &str,
    vk_path: &str,
    circuit: C,
) -> Result<(), Error> {
    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };

    set_config_k(params.k() as usize);

    let vk = keygen_vk(&params, &circuit).unwrap();
    println!("app vk generated");
    {
        let f = File::create(vk_path).unwrap();
        let mut writer = BufWriter::new(f);
        vk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
            .unwrap();
        writer.flush().unwrap();
    }

    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();

    println!("app pk generated");
    {
        let f = File::create(pk_path).unwrap();
        let mut writer = BufWriter::new(f);
        pk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
            .unwrap();
        writer.flush().unwrap();
    }

    Ok(())
}

/// Generate a proof for the regex verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `pk_path` - a file path of the proving key.
/// * `is_success` - is the proof should pass or not.
/// * `proof_path` - a file path of the output proof.
/// * `circuit` - a regex verification circuit.
pub fn prove<C: Circuit<Fr>>(
    params_path: &str,
    pk_path: &str,
    is_success: bool,
    proof_path: &str,
    circuit: C,
) -> Result<(), Error> {
    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    set_config_k(params.k() as usize);

    let prover = MockProver::run(params.k(), &circuit, vec![]).unwrap();
    if is_success {
        assert_eq!(prover.verify(), Ok(()));
    }else {
        assert_ne!(prover.verify(), Ok(()));
    }

    let pk = {
        let f = File::open(Path::new(pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let rng = thread_rng();
    let proof = {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[&[]],
            rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };
    {
        let f = File::create(proof_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&proof).unwrap();
        writer.flush().unwrap();
    };
    Ok(())
}

pub fn verify<C: Circuit<Fr>>(
    params_path: &str,
    vk_path: &str,
    proof_path: &str,
    _circuit: C,
) -> bool {
    let params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(Path::new(vk_path)).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let proof = {
        let mut f = File::open(&proof_path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&verifier_params);
    let verify_result = verify_proof::<_, VerifierGWC<_>, _, _, _>(
        verifier_params,
        &vk,
        strategy,
        &[&[]],
        &mut transcript,
    );

    return match verify_result {
        Ok(_value) => true,
        Err(_e) => false,
    };
}
