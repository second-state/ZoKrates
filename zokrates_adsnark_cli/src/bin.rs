//
// @file bin.rs
// @author Jacob Eberhardt <jacob.eberhardt@tu-berlin.de>
// @author Dennis Kuhnert <dennis.kuhnert@campus.tu-berlin.de>
// @date 2017

use bincode::{deserialize_from, serialize_into, Infinite};
use clap::{App, AppSettings, Arg, SubCommand};
use std::fs::File;
use std::io::{stdin, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::string::String;
use std::{env, io};
use zokrates_core::compile::compile;
use zokrates_core::ir;
use zokrates_core::proof_system::*;
use zokrates_field::field::{Field, FieldPrime};
use zokrates_fs_resolver::resolve as fs_resolve;
#[cfg(feature = "github")]
use zokrates_github_resolver::{is_github_import, resolve as github_resolve};

//Unused import preserved for future json support
//use serde_json::Value;

fn main() {
    cli().unwrap_or_else(|e| {
        println!("{}", e);
        std::process::exit(1);
    })
}

fn resolve(
    location: &Option<String>,
    source: &String,
) -> Result<(BufReader<File>, String, String), io::Error> {
    #[cfg(feature = "github")]
    {
        if is_github_import(source) {
            return github_resolve(location, source);
        };
    }
    fs_resolve(location, source)
}

fn cli() -> Result<(), String> {
    const FLATTENED_CODE_DEFAULT_PATH: &str = "out";
    const VERIFICATION_KEY_DEFAULT_PATH: &str = "verification.key";
    const PROVING_KEY_DEFAULT_PATH: &str = "proving.key";
    const VERIFICATION_CONTRACT_DEFAULT_PATH: &str = "verifier.sol";
    const WITNESS_DEFAULT_PATH: &str = "witness";
    const AUTH_PUBLIC_KEY_DEFAULT_PATH: &str = "authpublic.key";
    const AUTH_PRIVATE_KEY_DEFAULT_PATH: &str = "authprivate.key";
    const AUTH_PARAM_DEFAULT_PATH: &str = "authparam";
    const LABEL_DEFAULT_PATH: &str =  "label";
    const AUTHDATA_DEFAULT_PATH: &str =  "authdata";
    const PROOF_DEFAULT_PATH: &str = "proof";
    const JSON_PROOF_PATH: &str = "proof.json";

    // cli specification using clap library
    let matches = App::new("ZoKrates-ADSNARK")
    .setting(AppSettings::SubcommandRequiredElseHelp)
    .version(env!("CARGO_PKG_VERSION"))
    .author("Jacob Eberhardt, Thibaut Schaeffer, Stefan Deml")
    .about("Supports generation of ADSNARKs from high level language code including Smart Contracts for proof verification.")
    .subcommand(SubCommand::with_name("auth-setup")
        .about("Performs a key genetation for authenticator")
        .arg(Arg::with_name("auth-public-key-path")
            .short("p")
            .long("auth-public-key-path")
            .help("Path of the generated public key file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTH_PUBLIC_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("auth-private-key-path")
            .short("v")
            .long("auth-private-key-path")
            .help("Path of the generated private key file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTH_PRIVATE_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("authentication-parameters-path")
            .short("a")
            .long("authentication-parameters-path")
            .help("Path of the authentication public parameters file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTH_PARAM_DEFAULT_PATH)
        )
    )
    .subcommand(SubCommand::with_name("auth-sign")
        .about("Provide signatures to authenticate data")
        .arg(Arg::with_name("label-path")
            .short("l")
            .long("label-path")
            .help("Path of label file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(LABEL_DEFAULT_PATH)
        )
        .arg(Arg::with_name("auth-private-key-path")
            .short("v")
            .long("auth-private-key-path")
            .help("Path of the authenticator private key file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTH_PRIVATE_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("authenticated-data-path")
            .short("a")
            .long("authenticated-data-path")
            .help("Path to output the authenticated data")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTHDATA_DEFAULT_PATH)
        )
        .arg(Arg::with_name("arguments-count")
            .short("c")
            .long("arguments-count")
            .help("Number of arguments to sign")
            .takes_value(true)
            .required(true)
        )
        .arg(Arg::with_name("arguments")
            .short("g")
            .long("arguments")
            .help("Arguments to sign as a space separated list")
            .takes_value(true)
            .multiple(true) // allows multiple values
            .required(false)
        )
    )
    .subcommand(SubCommand::with_name("compile")
        .about("Compiles into flattened conditions. Produces two files: human-readable '.code' file for debugging and binary file")
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .help("Path of the source code")
            .value_name("FILE")
            .takes_value(true)
            .required(true)
        )
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .help("Path of the output file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(FLATTENED_CODE_DEFAULT_PATH)
        )
        .arg(Arg::with_name("light")
            .long("light")
            .help("Skip logs and human readable output")
            .required(false)
        )
    )
    .subcommand(SubCommand::with_name("compute-witness")
        .about("Calculates a witness for a given constraint system")
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .help("Path of compiled code")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(FLATTENED_CODE_DEFAULT_PATH)
        )
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .help("Path of the output file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(WITNESS_DEFAULT_PATH)
        )
        .arg(Arg::with_name("arguments")
            .short("a")
            .long("arguments")
            .help("Arguments for the program's main method as a space separated list")
            .takes_value(true)
            .multiple(true) // allows multiple values
            .required(false)
        )
        .arg(Arg::with_name("light")
            .long("light")
            .help("Skip logs and human readable output")
            .required(false)
        )
    )
    .subcommand(SubCommand::with_name("export-verifier")
        .about("Should export verifier as Solidity smart contract, currently not supported yet.")
        .arg(Arg::with_name("verification-key")
            .short("v")
            .long("verification-key")
            .help("Path of the verification key")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(VERIFICATION_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("auth-public-key-path")
            .short("p")
            .long("auth-public-key-path")
            .help("Path of the authenticator public key file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTH_PUBLIC_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .help("Path of the output file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(VERIFICATION_CONTRACT_DEFAULT_PATH)
        )
    )
    .subcommand(SubCommand::with_name("generate-proof")
        .about("Calculates a proof for a given constraint system, witness, and signatures.")
        .arg(Arg::with_name("witness")
            .short("w")
            .long("witness")
            .help("Path of the witness file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(WITNESS_DEFAULT_PATH)
        )
        .arg(Arg::with_name("provingkey")
            .short("p")
            .long("provingkey")
            .help("Path of the proving key file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(PROVING_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("jsonproofpath")
            .short("j")
            .long("jsonproofpath")
            .help("path of the JSON proof file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(JSON_PROOF_PATH)
        )
        .arg(Arg::with_name("proofpath")
            .short("o")
            .long("proofpath")
            .help("Path of the output proof file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(PROOF_DEFAULT_PATH)
        )
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .help("Path of compiled code")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(FLATTENED_CODE_DEFAULT_PATH)
        )
        .arg(Arg::with_name("authenticated-data-path")
            .short("a")
            .long("authenticated-data-path")
            .help("Path to the authenticated data")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTHDATA_DEFAULT_PATH)
        )
    )
    .subcommand(SubCommand::with_name("scheme-setup")
        .about("Performs a trusted setup for a given constraint system with authentication parameters")
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .help("Path of compiled code")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(FLATTENED_CODE_DEFAULT_PATH)
        )
        .arg(Arg::with_name("proving-key-path")
            .short("p")
            .long("proving-key-path")
            .help("Path of the generated proving key file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(PROVING_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("verification-key-path")
            .short("v")
            .long("verification-key-path")
            .help("Path of the generated verification key file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(VERIFICATION_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("authentication-parameters-path")
            .short("a")
            .long("authentication-parameters-path")
            .help("Path of the authentication public parameters file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTH_PARAM_DEFAULT_PATH)
        ).arg(Arg::with_name("light")
            .long("light")
            .help("Skip logs and human readable output")
            .required(false)
        )
    )
    .subcommand(SubCommand::with_name("verify-proof")
        .about("Verify proof of ADSNARK, fully contains the signature verifying process")
        .arg(Arg::with_name("label-path")
            .short("l")
            .long("label-path")
            .help("Path of label file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(LABEL_DEFAULT_PATH)
        )
        .arg(Arg::with_name("auth-public-key-path")
            .short("p")
            .long("auth-public-key-path")
            .help("Path of the authenticator public key file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTH_PUBLIC_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("authenticated-data-path")
            .short("a")
            .long("authenticated-data-path")
            .help("Path to output the authenticated data")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTHDATA_DEFAULT_PATH)
        )
        .arg(Arg::with_name("verification-key")
            .short("v")
            .long("verification-key")
            .help("Path of the verification key")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(VERIFICATION_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("proofpath")
            .short("i")
            .long("proofpath")
            .help("Path of the proof file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(PROOF_DEFAULT_PATH)
        )
    )
    .subcommand(SubCommand::with_name("verify-signature")
        .about("Check validity of authenticated data, fully contained in verify-proof")
        .arg(Arg::with_name("label-path")
            .short("l")
            .long("label-path")
            .help("Path of label file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(LABEL_DEFAULT_PATH)
        )
        .arg(Arg::with_name("auth-public-key-path")
            .short("p")
            .long("auth-public-key-path")
            .help("Path of the authenticator public key file")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTH_PUBLIC_KEY_DEFAULT_PATH)
        )
        .arg(Arg::with_name("authenticated-data-path")
            .short("a")
            .long("authenticated-data-path")
            .help("Path to output the authenticated data")
            .value_name("FILE")
            .takes_value(true)
            .required(false)
            .default_value(AUTHDATA_DEFAULT_PATH)
        )
    )
    .get_matches();


    match matches.subcommand() {
        ("compile", Some(sub_matches)) => {
            println!("Compiling {}\n", sub_matches.value_of("input").unwrap());

            let path = PathBuf::from(sub_matches.value_of("input").unwrap());

            let location = path
                .parent()
                .unwrap()
                .to_path_buf()
                .into_os_string()
                .into_string()
                .unwrap();

            let light = sub_matches.occurrences_of("light") > 0;

            let bin_output_path = Path::new(sub_matches.value_of("output").unwrap());

            let hr_output_path = bin_output_path.to_path_buf().with_extension("code");

            let file = File::open(path.clone()).unwrap();

            let mut reader = BufReader::new(file);

            let program_flattened: ir::Prog<FieldPrime> =
                compile(&mut reader, Some(location), Some(resolve))
                    .map_err(|e| format!("Compilation failed:\n\n {}", e))?;

            // number of constraints the flattened program will translate to.
            let num_constraints = program_flattened.constraint_count();

            // serialize flattened program and write to binary file
            let bin_output_file = File::create(&bin_output_path)
                .map_err(|why| format!("couldn't create {}: {}", bin_output_path.display(), why))?;

            let mut writer = BufWriter::new(bin_output_file);

            serialize_into(&mut writer, &program_flattened, Infinite)
                .map_err(|_| "Unable to write data to file.".to_string())?;

            if !light {
                // write human-readable output file
                let hr_output_file = File::create(&hr_output_path).map_err(|why| {
                    format!("couldn't create {}: {}", hr_output_path.display(), why)
                })?;

                let mut hrofb = BufWriter::new(hr_output_file);
                write!(&mut hrofb, "{}\n", program_flattened)
                    .map_err(|_| "Unable to write data to file.".to_string())?;
                hrofb
                    .flush()
                    .map_err(|_| "Unable to flush buffer.".to_string())?;
            }

            if !light {
                // debugging output
                println!("Compiled program:\n{}", program_flattened);
            }

            println!("Compiled code written to '{}'", bin_output_path.display());

            if !light {
                println!("Human readable code to '{}'", hr_output_path.display());
            }

            println!("Number of constraints: {}", num_constraints);
        }
        ("compute-witness", Some(sub_matches)) => {
            println!("Computing witness...");

            // read compiled program
            let path = Path::new(sub_matches.value_of("input").unwrap());
            let file = File::open(&path)
                .map_err(|why| format!("couldn't open {}: {}", path.display(), why))?;

            let mut reader = BufReader::new(file);

            let program_ast: ir::Prog<FieldPrime> =
                deserialize_from(&mut reader, Infinite).map_err(|why| why.to_string())?;

            // print deserialized flattened program
            if !sub_matches.is_present("light") {
                println!("{}", program_ast);
            }

            let expected_cli_args_count =
                program_ast.public_arguments_count() + program_ast.private_arguments_count();

            // get arguments
            let arguments: Vec<_> = match sub_matches.values_of("arguments") {
                // take inline arguments
                Some(p) => p
                    .map(|x| FieldPrime::try_from_dec_str(x).map_err(|_| x.to_string()))
                    .collect(),
                // take stdin arguments
                None => {
                    if expected_cli_args_count > 0 {
                        let mut stdin = stdin();
                        let mut input = String::new();
                        match stdin.read_to_string(&mut input) {
                            Ok(_) => {
                                input.retain(|x| x != '\n');
                                input
                                    .split(" ")
                                    .map(|x| {
                                        FieldPrime::try_from_dec_str(x).map_err(|_| x.to_string())
                                    })
                                    .collect()
                            }
                            Err(_) => Err(String::from("???")),
                        }
                    } else {
                        Ok(vec![])
                    }
                }
            }
            .map_err(|e| format!("Could not parse argument: {}", e))?;

            if arguments.len() != expected_cli_args_count {
                Err(format!(
                    "Wrong number of arguments. Given: {}, Required: {}.",
                    arguments.len(),
                    expected_cli_args_count
                ))?
            }

            let witness = program_ast
                .execute(&arguments)
                .map_err(|e| format!("Execution failed: {}", e))?;

            println!("\nWitness: \n\n{}", witness.format_outputs());

            // write witness to file
            let output_path = Path::new(sub_matches.value_of("output").unwrap());
            let output_file = File::create(&output_path)
                .map_err(|why| format!("couldn't create {}: {}", output_path.display(), why))?;

            let writer = BufWriter::new(output_file);

            witness
                .write(writer)
                .map_err(|why| format!("could not save witness: {:?}", why))?;
        }
        ("scheme-setup", Some(sub_matches)) => {
            let scheme = &BBFR15 {};

            println!("Performing scheme setup...");

            let path = Path::new(sub_matches.value_of("input").unwrap());
            let file = File::open(&path)
                .map_err(|why| format!("couldn't open {}: {}", path.display(), why))?;

            let mut reader = BufReader::new(file);

            let program: ir::Prog<FieldPrime> =
                deserialize_from(&mut reader, Infinite).map_err(|why| format!("{:?}", why))?;

            // print deserialized flattened program
            if !sub_matches.is_present("light") {
                println!("{}", program);
            }

            // get paths for proving keys, verification keys, and authentication parameters
            let pk_path = sub_matches.value_of("proving-key-path").unwrap();
            let vk_path = sub_matches.value_of("verification-key-path").unwrap();
            let auth_pap_path = sub_matches.value_of("authentication-parameters-path").unwrap();
            // run setup phase
            scheme.setup(program, pk_path, vk_path, auth_pap_path);

            println!("Scheme setup done")
        }
        ("export-verifier", Some(_)) => {
            {
                println!("Exporter not supported yet!");
            }
        }
        ("generate-proof", Some(sub_matches)) => {
            println!("Generating proof...");

            let scheme = &BBFR15 {};

            // deserialize witness
            let witness_path = Path::new(sub_matches.value_of("witness").unwrap());
            let witness_file = match File::open(&witness_path) {
                Ok(file) => file,
                Err(why) => panic!("couldn't open {}: {}", witness_path.display(), why),
            };

            let witness = ir::Witness::read(witness_file)
                .map_err(|why| format!("could not load witness: {:?}", why))?;

            //get path from files
            let pk_path = sub_matches.value_of("provingkey").unwrap();
            let json_proof_path = sub_matches.value_of("jsonproofpath").unwrap();
            let proof_path = sub_matches.value_of("proofpath").unwrap();
            let authdata_path = sub_matches.value_of("authenticated-data-path").unwrap();

            let program_path = Path::new(sub_matches.value_of("input").unwrap());
            let program_file = File::open(&program_path)
                .map_err(|why| format!("couldn't open {}: {}", program_path.display(), why))?;

            let mut reader = BufReader::new(program_file);

            let program: ir::Prog<FieldPrime> =
                deserialize_from(&mut reader, Infinite).map_err(|why| format!("{:?}", why))?;

            println!(
                "generate-proof successful: {:?}",
                scheme.generate_proof(program, witness, pk_path, proof_path, authdata_path, json_proof_path)
            );
        }
        ("auth-setup", Some(sub_matches)) => {
            println!("Start authentication setup...");

            let scheme = &BBFR15 {};

            //get path from files
            let pk_path = sub_matches.value_of("auth-public-key-path").unwrap();
            let sk_path = sub_matches.value_of("auth-private-key-path").unwrap();
            let pap_path = sub_matches.value_of("authentication-parameters-path").unwrap();
            //run setup phase
            scheme.auth_setup(pk_path, sk_path, pap_path);

            println!("Authentication setup done");
        }
        ("auth-sign", Some(sub_matches)) => {
            println!("Start signing...");

            let scheme = &BBFR15 {};

            //get path from files
            let label_path = sub_matches.value_of("label-path").unwrap();
            let sk_path = sub_matches.value_of("auth-private-key-path").unwrap();
            let authdata_path = sub_matches.value_of("authenticated-data-path").unwrap();
            let expected_cli_args_count =  sub_matches.value_of("arguments-count").unwrap().parse::<usize>().unwrap_or(0);

            if expected_cli_args_count <= 0 {
                Err(
                    "No variables to sign!"
                )?
            }

            let arguments: Vec<_> = match sub_matches.values_of("arguments") {
                // take inline arguments
                Some(p) => p
                    .map(|x| FieldPrime::try_from_dec_str(x).map_err(|_| x.to_string()))
                    .collect(),
                // take stdin arguments
                None => {
                    if expected_cli_args_count > 0 {
                        let mut stdin = stdin();
                        let mut input = String::new();
                        match stdin.read_to_string(&mut input) {
                            Ok(_) => {
                                input.retain(|x| x != '\n');
                                input
                                    .split(" ")
                                    .map(|x| {
                                        FieldPrime::try_from_dec_str(x).map_err(|_| x.to_string())
                                    })
                                    .collect()
                            }
                            Err(_) => Err(String::from("???")),
                        }
                    } else {
                        Ok(vec![])
                    }
                }
            }
            .map_err(|e| format!("Could not parse argument: {}", e))?;

            if arguments.len() != expected_cli_args_count {
                Err(format!(
                    "Wrong number of arguments. Given: {}, Required: {}.",
                    arguments.len(),
                    expected_cli_args_count
                ))?
            }

            //Sign arguments with labels
            scheme.auth_sign(&arguments, sk_path, label_path, authdata_path);
            println!("Signing process success, {} arguments signed", arguments.len());
        }
        ("verify-signature", Some(sub_matches)) => {
            println!("Start verifying signatures...");

            let scheme = &BBFR15 {};

            //get path from files
            let label_path = sub_matches.value_of("label-path").unwrap();
            let auth_pk_path = sub_matches.value_of("auth-public-key-path").unwrap();
            let authdata_path = sub_matches.value_of("authenticated-data-path").unwrap();

            //Verifies signature
            let result = scheme.verify_signature(auth_pk_path, label_path, authdata_path);
            println!("Signature verification result : {}", result);
        }
        ("verify-proof", Some(sub_matches)) => {
            println!("Start verifying proof...");

            let scheme = &BBFR15 {};

            //get path from files
            let label_path = sub_matches.value_of("label-path").unwrap();
            let auth_pk_path = sub_matches.value_of("auth-public-key-path").unwrap();
            let authdata_path = sub_matches.value_of("authenticated-data-path").unwrap();
            let vk_path = sub_matches.value_of("verification-key").unwrap();
            let proof_path = sub_matches.value_of("proofpath").unwrap();

            //Verifies full proof
            let result = scheme.verify_proof(vk_path, auth_pk_path, label_path, authdata_path, proof_path);
            println!("Proof verification result : {}", result);
        }
        _ => unreachable!(),
    }
    Ok(())
}
