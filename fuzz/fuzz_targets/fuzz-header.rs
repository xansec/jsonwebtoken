#![no_main]
//use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use libfuzzer_sys::fuzz_target;


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

fuzz_target!(| input: (&[u8], String, String, String, usize) | {
    let my_claims =
        Claims { sub: input.1.to_owned(), company: input.2.to_owned(), exp: input.4 };
    let key = input.0;

    let header =
        Header { kid: Some(input.3.to_owned()), alg: Algorithm::HS512, ..Default::default() };

    let token = match encode(&header, &my_claims, &EncodingKey::from_secret(key)) {
        Ok(t) => t,
        Err(_) => return, // in practice you would return the error
    };
    //println!("{:?}", token);

    let _token_data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(key),
        &Validation::new(Algorithm::HS512),
    ) {
        Ok(c) => c,
        Err(_) => return,
        //Err(err) => match *err.kind() {
            //ErrorKind::InvalidToken => panic!(), // Example on how to handle a specific error
            //_ => std::panic::panic_any(err),
        //},
    };
    //println!("{:?}", token_data.claims);
    //println!("{:?}", token_data.header);
});
