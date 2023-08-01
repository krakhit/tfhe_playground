use tfhe_playground::*;
use tfhe::core_crypto::{prelude::{*, polynomial_algorithms::{polynomial_wrapping_add_assign, 
    polynomial_wrapping_add_mul_assign, polynomial_wrapping_add_multisum_assign, polynomial_wrapping_mul, 
    polynomial_wrapping_sub_assign}}};
use rand::{Rng, thread_rng};


//small size parameters
#[test]
pub fn small_entropy_test(){
    //params toy : Note q must be divisible by p
    let modulus_q:i64 = 32;
    let modulus_p:i64 = 4;
    // N>k for problem to be well defined
    let k = 2;
    let N = 4; 
    
    // note that if the modulus is much higher than the range of coefficients it avoids all edge cases where 
    // error and rounding gives slightly incorrect results
    let mut rng = thread_rng();
    let mut input_msg:Vec<i64> =Vec::new();
    //play with the range and modulus to get edge cases
    for i in 0..=N-1{
    input_msg.push(rng.gen_range(-modulus_p/2..modulus_p/2));
    }
    // will get a panic error if the key is of low hamming weight 
    let (cipher_text_poly,glwe_poly_list) = encrypt_glwe(input_msg.clone(), modulus_p, modulus_q, N, k);
    let decrypted_text = decrypt_glwe(cipher_text_poly, glwe_poly_list, modulus_p, modulus_q, N, k);
    //sanity check
    assert_vector_eq(input_msg, decrypted_text);
}

///large size parameters 
#[test]
pub fn large_entropy_test(){
    let modulus_q:i64 = 4294967296i64;  //very large modulus
    //smaller plain text modulus (entries in plain text are modulo p)
    let modulus_p:i64 = 4096i64;
    //<delta/2 is the threshold for proper decryption, It is automatically taken into account in the decrypt function
    let delta:i64 = (modulus_q.clone() as i64)/(modulus_p.clone() as i64);
    //number of secret vectors 
    let k:usize = 8;
    // Polynomials are m_0 +m_1 X +... + m_{N-1}X^{N-1} and polynomial multiplications are modded by X^N+1 
    let N:usize = 16; 
    let mut rng = thread_rng();
    let mut input_msg:Vec<i64> =Vec::new();
    //play with the range and modulus to get edge cases
    for i in 0..=N-1{
    input_msg.push(rng.gen_range(-modulus_p/2..modulus_p/2));
    }
    // will get a panic error if the key is of low hamming weight 
    let (cipher_text_poly,glwe_poly_list) = encrypt_glwe(input_msg.clone(), modulus_p, modulus_q, N, k);
    let decrypted_text = decrypt_glwe(cipher_text_poly, glwe_poly_list, modulus_p, modulus_q, N, k);
    //sanity check
    assert_vector_eq(input_msg, decrypted_text);
}