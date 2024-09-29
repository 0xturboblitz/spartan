// use ark_ec::bn::G1Projective;
// Code borrowed from Nova-Scotia https://github.com/nalinbhardwaj/Nova-Scotia
use super::Instance;
// use ff::PrimeField;
// use secq256k1::AffinePoint;
// use secq256k1::FieldBytes;
use ark_bn254::{Fr, G1Projective, G1Affine, G2Projective, G2Affine};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, BigInt};
use ark_serialize::CanonicalDeserialize;


use std::path::PathBuf;
use byteorder::{LittleEndian, ReadBytesExt};
// use group::Group;
use itertools::Itertools;
use std::{
    collections::HashMap,
    io::{BufReader, Error, ErrorKind, Read, Result, Seek, SeekFrom},
};

pub type Constraint<Fr> = (Vec<(usize, Fr)>, Vec<(usize, Fr)>, Vec<(usize, Fr)>);

#[derive(Clone)]
pub struct R1CS<Fr> {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
    pub constraints: Vec<Constraint<Fr>>,
}

// R1CSFile's header
#[derive(Debug, Default)]
pub struct Header {
    pub field_size: u32,
    pub prime_size: Vec<u8>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
    pub n_labels: u64,
    pub n_constraints: u32,
}

// R1CSFile parse result
#[derive(Debug, Default)]
pub struct R1CSFile<Fr> {
    pub version: u32,
    pub header: Header,
    pub constraints: Vec<Constraint<Fr>>,
    pub wire_mapping: Vec<u64>,
}

use std::fs::OpenOptions;
use std::path::Path;

pub fn load_as_spartan_inst(circuit_file: PathBuf, num_pub_inputs: usize) -> Instance<Fr> {
    let (r1cs, _) = load_r1cs_from_bin_file::<G1Projective>(&circuit_file);
    let spartan_inst = convert_to_spartan_r1cs(&r1cs, num_pub_inputs);
    spartan_inst
}
  
fn convert_to_spartan_r1cs<Fr: PrimeField>(
    r1cs: &R1CS<Fr>,
    num_pub_inputs: usize,
) -> Instance<Fr> {
    let num_cons = r1cs.constraints.len();
    let num_vars = r1cs.num_variables;
    let num_inputs = num_pub_inputs;
  
    let mut A = vec![];
    let mut B = vec![];
    let mut C = vec![];
  
    for (i, constraint) in r1cs.constraints.iter().enumerate() {
        let (a, b, c) = constraint;
  
        for (j, coeff) in a.iter() {
            let bytes = *coeff;
  
            A.push((i, *j, bytes));
        }
  
        for (j, coeff) in b.iter() {
            let bytes = *coeff;
            B.push((i, *j, bytes));
        }
  
        for (j, coeff) in c.iter() {
            let bytes = *coeff;
            C.push((i, *j, bytes));
        }
    }
  
    let inst = Instance::<Fr>::new(
        num_cons,
        num_vars,
        num_inputs,
        A.as_slice(),
        B.as_slice(),
        C.as_slice(),
    )
    .unwrap();
  
    inst
}

pub fn load_r1cs_from_bin_file<G1: CurveGroup>(filename: &Path) -> (R1CS<Fr>, Vec<usize>) {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    load_r1cs_from_bin::<G1, _>(BufReader::new(reader))
}

pub fn load_r1cs_from_bin<G1: CurveGroup, R: Read + Seek>(reader: R) -> (R1CS<Fr>, Vec<usize>) {
    let file = from_reader::<G1, R>(reader).expect("unable to read.");
    let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
    let num_variables = file.header.n_wires as usize;
    let num_aux = num_variables - num_inputs;
    (
        R1CS {
            num_aux,
            num_inputs,
            num_variables,
            constraints: file.constraints,
        },
        file.wire_mapping.iter().map(|e| *e as usize).collect_vec(),
    )
}

pub(crate) fn read_field<R: Read>(mut reader: R) -> Result<Fr> {
    Fr::deserialize_compressed(&mut reader).map_err(|e| Error::new(ErrorKind::InvalidData, e))
}

fn read_header<R: Read>(mut reader: R, size: u64) -> Result<Header> {
    let field_size = reader.read_u32::<LittleEndian>()?;
    let mut prime_size = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime_size)?;
    if size != 32 + field_size as u64 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid header section size",
        ));
    }

    Ok(Header {
        field_size,
        prime_size,
        n_wires: reader.read_u32::<LittleEndian>()?,
        n_pub_out: reader.read_u32::<LittleEndian>()?,
        n_pub_in: reader.read_u32::<LittleEndian>()?,
        n_prv_in: reader.read_u32::<LittleEndian>()?,
        n_labels: reader.read_u64::<LittleEndian>()?,
        n_constraints: reader.read_u32::<LittleEndian>()?,
    })
}

fn read_constraint_vec<R: Read>(mut reader: R) -> Result<Vec<(usize, Fr)>> {
    let n_vec = reader.read_u32::<LittleEndian>()? as usize;
    let mut vec = Vec::with_capacity(n_vec);
    for _ in 0..n_vec {
        vec.push((
            reader.read_u32::<LittleEndian>()? as usize,
            read_field(&mut reader)?, // Removed extra generic argument
        ));
    }
    Ok(vec)
}

fn read_constraints<R: Read>(
    mut reader: R,
    header: &Header,
) -> Result<Vec<Constraint<Fr>>> {
    // todo check section size
    let mut vec = Vec::with_capacity(header.n_constraints as usize);
    for _ in 0..header.n_constraints {
        vec.push((
            read_constraint_vec(&mut reader)?,
            read_constraint_vec(&mut reader)?,
            read_constraint_vec(&mut reader)?,
        ));
    }
    Ok(vec)
}

fn read_map<R: Read>(mut reader: R, size: u64, header: &Header) -> Result<Vec<u64>> {
    if size != header.n_wires as u64 * 8 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid map section size",
        ));
    }
    let mut vec = Vec::with_capacity(header.n_wires as usize);
    for _ in 0..header.n_wires {
        vec.push(reader.read_u64::<LittleEndian>()?);
    }
    if vec[0] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Wire 0 should always be mapped to 0",
        ));
    }
    Ok(vec)
}

pub fn from_reader<G1: CurveGroup, R: Read + Seek>(mut reader: R) -> Result<R1CSFile<Fr>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != [0x72, 0x31, 0x63, 0x73] {
        // magic = "r1cs"
        return Err(Error::new(ErrorKind::InvalidData, "Invalid magic number"));
    }

    let version = reader.read_u32::<LittleEndian>()?;
    if version != 1 {
        return Err(Error::new(ErrorKind::InvalidData, "Unsupported version"));
    }

    let num_sections = reader.read_u32::<LittleEndian>()?;

    // section type -> file offset
    let mut section_offsets = HashMap::<u32, u64>::new();
    let mut section_sizes = HashMap::<u32, u64>::new();

    // get file offset of each section
    for _ in 0..num_sections {
        let section_type = reader.read_u32::<LittleEndian>()?;
        let section_size = reader.read_u64::<LittleEndian>()?;
        let offset = reader.seek(SeekFrom::Current(0))?;
        section_offsets.insert(section_type, offset);
        section_sizes.insert(section_type, section_size);
        reader.seek(SeekFrom::Current(section_size as i64))?;
    }

    let header_type = 1;
    let constraint_type = 2;
    let wire2label_type = 3;

    reader.seek(SeekFrom::Start(*section_offsets.get(&header_type).unwrap()))?;
    let header = read_header(&mut reader, *section_sizes.get(&header_type).unwrap())?;
    if header.field_size != 32 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "This parser only supports 32-byte fields",
        ));
    }
    // if header.prime_size != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430") {
    //     return Err(Error::new(ErrorKind::InvalidData, "This parser only supports bn256"));
    // }

    reader.seek(SeekFrom::Start(
        *section_offsets.get(&constraint_type).unwrap(),
    ))?;
    let constraints = read_constraints(&mut reader, &header)?;

    reader.seek(SeekFrom::Start(
        *section_offsets.get(&wire2label_type).unwrap(),
    ))?;
    let wire_mapping = read_map(
        &mut reader,
        *section_sizes.get(&wire2label_type).unwrap(),
        &header,
    )?;

    Ok(R1CSFile {
        version,
        header,
        constraints,
        wire_mapping,
    })
}

pub fn load_witness_from_bin_reader<R: Read>(mut reader: R) -> Result<Vec<Fr>> {
    let mut wtns_header = [0u8; 4];
    reader.read_exact(&mut wtns_header)?;
    if wtns_header != [119, 116, 110, 115] {
        // ruby -e 'p "wtns".bytes' => [119, 116, 110, 115]
        panic!("invalid file header");
    }
    let version = reader.read_u32::<LittleEndian>()?;
    // println!("wtns version {}", version);
    if version > 2 {
        panic!("unsupported file version");
    }
    let num_sections = reader.read_u32::<LittleEndian>()?;
    if num_sections != 2 {
        panic!("invalid num sections");
    }
    // read the first section
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 1 {
        panic!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != 4 + 32 + 4 {
        panic!("invalid section len")
    }
    let field_size = reader.read_u32::<LittleEndian>()?;
    if field_size != 32 {
        panic!("invalid field byte size");
    }
    let mut prime = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime)?;
    // if prime != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430") {
    //     bail!("invalid curve prime {:?}", prime);
    // }
    let witness_len = reader.read_u32::<LittleEndian>()?;
    // println!("witness len {}", witness_len);
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 2 {
        panic!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != u64::from(witness_len) * u64::from(field_size) {
        panic!("invalid witness section size {}", sec_size);
    }
    let mut result = Vec::with_capacity(witness_len as usize);
    for _ in 0..witness_len {
        result.push(read_field(&mut reader)?);
    }
    Ok(result)
}