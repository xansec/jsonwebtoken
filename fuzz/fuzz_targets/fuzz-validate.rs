#![no_main]
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String,
    sub: String,
    company: String,
    exp: usize,
}

/***
impl Arbitrary<'_> for Claims {
    fn arbitrary<U>(raw: &mut U) -> Result<Self, U::Error>
    where
        U: Unstructured + ?Sized
    {
        let mut buf = [0; 4];
        raw.fill_buffer(&mut buf)?;
        let aud = buf[0].to_owned();
        let sub = buf[1].to_owned();
        let company = buf[2].to_owned();
        let exp = buf[3].read_u32::<BigEndian>().unwrap();
        Ok(Claims { aud, sub, company, exp })
    }
}
***/


// fuzz_target!(| claims: Claims | {
fuzz_target!(| input: (&[u8], String, String, String, int) | {
    let key = input.0;
    let claims = Claims {
        aud: input.1.to_owned(),
        sub: input.2.to_owned(),
        company: input.3.to_owned(),
        exp: input.4,
    };
    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(key)) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    let mut validation = Validation::new(Algorithm::HS256);
    validation.sub = Some(input.2);
    validation.set_audience(&[input.1]);
    let _ = match decode::<Claims>(&token, &DecodingKey::from_secret(key), &validation) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            //ErrorKind::InvalidToken => panic!("Token is invalid"), // Example on how to handle a specific error
            //ErrorKind::InvalidIssuer => panic!("Issuer is invalid"), // Example on how to handle a specific error
            _ => panic!(err),
        },
    };
    //println!("{:?}", token_data.claims);
    //println!("{:?}", token_data.header);
});
