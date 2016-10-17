extern crate byteorder;
extern crate docopt;
extern crate rustc_serialize;
extern crate sodiumoxide;

use byteorder::{BigEndian, ByteOrder};
use rustc_serialize::hex::FromHex;
use sodiumoxide::crypto::{secretbox, sign};
use sodiumoxide::crypto::hash::sha512;

use std::io::prelude::*;

const DEFAULT_PLAINTEXT_CHUNK_LEN: usize = 1 << 20;

pub type Nonce = [u8; 16];

fn make_secretbox_nonce(nonce: &Nonce, chunk_num: u64) -> secretbox::Nonce {
    let mut buf = [0; secretbox::NONCEBYTES];
    buf[0..16].copy_from_slice(nonce);
    BigEndian::write_u64(&mut buf[16..24], chunk_num);
    secretbox::Nonce::from_slice(&buf).unwrap()
}

const SIGNATURE_PREFIX: &'static [u8] = b"keybase chat attachment\0";

fn make_signature_input(plaintext: &[u8],
                        enckey: &secretbox::Key,
                        encnonce: &secretbox::Nonce)
                        -> Vec<u8> {
    let mut signature_input = Vec::new();
    signature_input.extend_from_slice(SIGNATURE_PREFIX);
    signature_input.extend_from_slice(&enckey[..]);
    signature_input.extend_from_slice(&encnonce[..]);
    let digest = sha512::hash(plaintext);
    signature_input.extend_from_slice(&digest[..]);
    signature_input
}

fn get_packet_len(plaintext_chunk_len: usize) -> usize {
    plaintext_chunk_len + sign::SIGNATUREBYTES + secretbox::MACBYTES
}

fn seal_packet(plaintext: &[u8],
               chunk_num: u64,
               enckey: &secretbox::Key,
               signkey: &sign::SecretKey,
               nonce: &Nonce)
               -> Vec<u8> {
    let secretbox_nonce = make_secretbox_nonce(nonce, chunk_num);
    let signature_input = make_signature_input(plaintext, enckey, &secretbox_nonce);
    let signature = sign::sign_detached(&signature_input, signkey);
    let mut signed_chunk = Vec::new();
    signed_chunk.extend_from_slice(&signature[..]);
    signed_chunk.extend_from_slice(plaintext);
    let ciphertext = secretbox::seal(&signed_chunk, &secretbox_nonce, enckey);
    ciphertext
}

fn open_packet(packet: &[u8],
               chunk_num: u64,
               enckey: &secretbox::Key,
               verifykey: &sign::PublicKey,
               nonce: &Nonce)
               -> Result<Vec<u8>, Error> {
    let secretbox_nonce = make_secretbox_nonce(nonce, chunk_num);
    let signed_chunk = try!(secretbox::open(packet, &secretbox_nonce, enckey)
        .map_err(|_| Error::BadSecretbox));
    if signed_chunk.len() < sign::SIGNATUREBYTES {
        return Err(Error::ShortSignature);
    }
    let signature = sign::Signature::from_slice(&signed_chunk[0..sign::SIGNATUREBYTES]).unwrap();
    let plaintext = &signed_chunk[sign::SIGNATUREBYTES..];
    let signature_input = make_signature_input(plaintext, enckey, &secretbox_nonce);
    let valid_signature = sign::verify_detached(&signature, &signature_input, verifykey);
    if !valid_signature {
        return Err(Error::BadSignature);
    }
    Ok(plaintext.to_vec())
}

pub struct Encoder {
    enckey: secretbox::Key,
    signkey: sign::SecretKey,
    nonce: Nonce,
    buf: Vec<u8>,
    chunk_num: u64,
    plaintext_chunk_len: usize,
}

impl Encoder {
    pub fn new(enckey: secretbox::Key, signkey: sign::SecretKey, nonce: Nonce) -> Encoder {
        Encoder {
            enckey: enckey,
            signkey: signkey,
            nonce: nonce,
            buf: Vec::new(),
            chunk_num: 0,
            plaintext_chunk_len: DEFAULT_PLAINTEXT_CHUNK_LEN,
        }
    }

    fn set_plaintext_chunk_len_for_testing(&mut self, len: usize) {
        self.plaintext_chunk_len = len;
    }

    fn seal_one_packet(&mut self, chunk_len: usize) -> Vec<u8> {
        let packet = {
            let plaintext = &self.buf[0..chunk_len];
            seal_packet(plaintext,
                        self.chunk_num,
                        &self.enckey,
                        &self.signkey,
                        &self.nonce)
        };
        self.chunk_num += 1;
        self.buf.drain(0..chunk_len);
        packet
    }

    pub fn write(&mut self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        self.buf.extend_from_slice(input);
        while self.buf.len() >= self.plaintext_chunk_len {
            let packet_size = self.plaintext_chunk_len;
            let packet = self.seal_one_packet(packet_size);
            output.extend_from_slice(&packet);
        }
        output
    }

    pub fn finish(&mut self) -> Vec<u8> {
        assert!(self.buf.len() < self.plaintext_chunk_len);
        let buf_len = self.buf.len();
        let packet = self.seal_one_packet(buf_len);
        packet
    }
}

pub struct Decoder {
    enckey: secretbox::Key,
    verifykey: sign::PublicKey,
    nonce: Nonce,
    buf: Vec<u8>,
    chunk_num: u64,
    packet_len: usize,
}

impl Decoder {
    pub fn new(enckey: secretbox::Key, verifykey: sign::PublicKey, nonce: Nonce) -> Decoder {
        Decoder {
            enckey: enckey,
            verifykey: verifykey,
            nonce: nonce,
            buf: Vec::new(),
            chunk_num: 0,
            packet_len: get_packet_len(DEFAULT_PLAINTEXT_CHUNK_LEN),
        }
    }

    fn set_plaintext_chunk_len_for_testing(&mut self, plaintext_chunk_len: usize) {
        self.packet_len = get_packet_len(plaintext_chunk_len);
    }

    fn open_one_packet(&mut self, packet_len: usize) -> Result<Vec<u8>, Error> {
        let plaintext = try!({
            let packet = &self.buf[0..packet_len];
            open_packet(packet,
                        self.chunk_num,
                        &self.enckey,
                        &self.verifykey,
                        &self.nonce)
        });
        self.chunk_num += 1;
        self.buf.drain(0..packet_len);
        Ok(plaintext)
    }

    pub fn write(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        self.buf.extend_from_slice(input);
        while self.buf.len() >= self.packet_len {
            let packet_len = self.packet_len;
            let chunk = try!(self.open_one_packet(packet_len));
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }

    pub fn finish(&mut self) -> Result<Vec<u8>, Error> {
        assert!(self.buf.len() < self.packet_len);
        let buf_len = self.buf.len();
        let plaintext = try!(self.open_one_packet(buf_len));
        Ok(plaintext)
    }
}

#[derive(Debug)]
pub enum Error {
    BadSecretbox,
    ShortSignature,
    BadSignature,
}

fn cmd_seal(enckey: secretbox::Key, signkey: sign::SecretKey, nonce: Nonce, chunk_len: Option<usize>) {
    let mut encoder = Encoder::new(enckey, signkey, nonce);
    if let Some(chunk_len) = chunk_len {
        encoder.set_plaintext_chunk_len_for_testing(chunk_len);
    }
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let mut buf = [0; 4096];
    loop {
        let num = stdin.read(&mut buf).unwrap();
        if num == 0 {
            break;
        }
        let output = encoder.write(&buf[0..num]);
        stdout.write_all(&output).unwrap();
    }
    let output = encoder.finish();
    stdout.write_all(&output).unwrap();
}

fn cmd_open(enckey: secretbox::Key, verifykey: sign::PublicKey, nonce: Nonce, chunk_len: Option<usize>) {
    let mut decoder = Decoder::new(enckey, verifykey, nonce);
    if let Some(chunk_len) = chunk_len {
        decoder.set_plaintext_chunk_len_for_testing(chunk_len);
    }
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let mut buf = [0; 4096];
    loop {
        let num = stdin.read(&mut buf).unwrap();
        if num == 0 {
            break;
        }
        let output = decoder.write(&buf[0..num]).unwrap();
        stdout.write_all(&output).unwrap();
    }
    let output = decoder.finish().unwrap();
    stdout.write_all(&output).unwrap();
}

const USAGE: &'static str = "
Usage:
    signencrypt seal [options]
    signencrypt open [options]

Options:
    --help
    --enckey=<enckey>        the 32-byte encryption key (in hex)
    --signkey=<signkey>      the 64-byte signing private key (in hex)
    --verifykey=<verifykey>  the 32-byte signing public  key (in hex)
    --nonce=<nonce>          the 16-byte nonce
    --chunklen=<chunklen>    the size of plaintext chunks, for testing, default 2^20 bytes
";

#[derive(Debug, RustcDecodable)]
struct Args {
    flag_enckey: Option<String>,
    flag_signkey: Option<String>,
    flag_verifykey: Option<String>,
    flag_nonce: Option<String>,
    flag_chunklen: Option<usize>,
    cmd_seal: bool,
    cmd_open: bool,
}

macro_rules! eprintln {
    ($($tt:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(&mut ::std::io::stderr(), $($tt)*);
    }}
}

fn decode_hex_arg(arg: &str, name: &str, dest: &mut [u8]) {
    let res = arg.from_hex();
    if let Err(_) = res {
        eprintln!("arg \"{}\" is invalid hex", arg);
        std::process::exit(1);
    }
    let bytes = res.unwrap();
    if bytes.len() != dest.len() {
        eprintln!("expected arg \"{}\" to decode to {} bytes, but found {}",
                  name,
                  dest.len(),
                  bytes.len());
        std::process::exit(1);
    }
    dest.copy_from_slice(&bytes);
}

fn main() {
    assert!(sodiumoxide::init());
    let args: Args = docopt::Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    let mut enckey_bytes = [0u8; secretbox::KEYBYTES];
    if let Some(ref arg) = args.flag_enckey {
        decode_hex_arg(arg, "enckey", &mut enckey_bytes);
    }
    let enckey = secretbox::Key::from_slice(&enckey_bytes).unwrap();

    let mut signkey_bytes = *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00;j'\xbc\xce\xb6\xa4-b\xa3\xa8\xd0*o\rse2\x15w\x1d\xe2C\xa6:\xc0H\xa1\x8bY\xda)";
    if let Some(ref arg) = args.flag_signkey {
        decode_hex_arg(arg, "signkey", &mut signkey_bytes);
    }
    let signkey = sign::SecretKey::from_slice(&signkey_bytes).unwrap();

    let mut verifykey_bytes = *b";j'\xbc\xce\xb6\xa4-b\xa3\xa8\xd0*o\rse2\x15w\x1d\xe2C\xa6:\xc0H\xa1\x8bY\xda)";
    if let Some(ref arg) = args.flag_verifykey {
        decode_hex_arg(arg, "verifykey", &mut verifykey_bytes);
    }
    let verifykey = sign::PublicKey::from_slice(&verifykey_bytes).unwrap();

    let mut nonce = [0u8; 16];
    if let Some(ref arg) = args.flag_nonce {
        decode_hex_arg(arg, "nonce", &mut nonce);
    }

    if args.cmd_seal {
        cmd_seal(enckey, signkey, nonce, args.flag_chunklen);
    } else if args.cmd_open {
        cmd_open(enckey, verifykey, nonce, args.flag_chunklen);
    } else {
        unreachable!();
    }
}
