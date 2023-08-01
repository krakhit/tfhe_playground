use tfhe::core_crypto::{prelude::{*, polynomial_algorithms::{polynomial_wrapping_add_assign, 
    polynomial_wrapping_add_mul_assign, polynomial_wrapping_add_multisum_assign, polynomial_wrapping_mul, 
    polynomial_wrapping_sub_assign}}};
use rand::{Rng, thread_rng};

///converts a vector of i64 elements to a vector of u64 elements
pub fn convert_Vi64_to_Vu64(input_vec: Vec<i64>)-> Vec<u64> {
    input_vec.iter().map(|&x| x as u64).collect()
}

///converts a vector of u64 elements to a vector of i64 elements
pub fn convert_Vu64_to_Vi64(input_vec: Vec<u64>)-> Vec<i64> {
    input_vec.iter().map(|&x| x as i64).collect()
}

///divides a scalar i64 by another i64 with round function correctly applied. Outputs the result
/// in i64 format
pub fn div_by_delta(input:i64,delta:i64)->i64{
    let temp = ((input as f64)/(delta as f64)).round();
    temp as i64 
}

///Given a vector of i64 elements, computes modulo operation on each element
pub fn modular_red_vec (input:Vec<i64>,modulus:i64)->Vec<i64>{
    input.iter().map(|&x| x%modulus).collect()
}

///Given 2 vectors each with i64 elements, computes vector addition followed by modular reduction
/// Panics when vectors are of unequal length
pub fn add_vecs_with_mod_red(input_1:Vec<i64>,input_2:Vec<i64>,modulus:i64) -> Vec<i64>{
    assert_eq!(input_1.len(),input_2.len());
    let mut res =Vec::new();
    for i in 0..=input_1.len()-1{
        res.push((input_1[i]+input_2[i])%modulus);
    }
    res
}

///Performs assertion test that 2 vectors are equal   
pub fn assert_vector_eq(input_1:Vec<i64>,input_2:Vec<i64>) {
    assert_eq!(input_1.len(),input_2.len());
    for i in 0..=input_1.len()-1{
        assert_eq!(input_1[i],input_2[i])
    }
}

//generates a GLWE secret key list in Polynomial form given the Polynomial size N and glwe size k+1
pub fn generate_glwe_secret_key (polynomial_size:PolynomialSize,glwe_size:GlweSize) -> PolynomialList<Vec<u64>> {
    let mut rng = thread_rng();
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();

    let mut secret_generator =
    SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    let glwe_secret_key:GlweSecretKey<Vec<u64>> = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_size.to_glwe_dimension(),
        polynomial_size,
        &mut secret_generator,
    );
    PolynomialList::from_container(glwe_secret_key.into_container(),polynomial_size)
}

/// Given a plain text M (vector of i64) and GLWE parameters Plain text modulus: p, cipher text modulus :q such that p divides q,
/// the ring dimension: N and k where GLWE dimension = k+1, the function outputs the GLWE encrypted cipher text polynomial list (k+1)
/// \(A_0,A_1,A_2,...,A_{k-1},B)\) where B = A.S + M * delta + E
pub fn encrypt_glwe(plaintext:Vec<i64>, modulus_p:i64, modulus_q: i64, N:usize, k:usize) -> (PolynomialList<Vec<u64>>,PolynomialList<Vec<u64>>) {
    let glwe_size = GlweSize(k+1);
    let polynomial_size = PolynomialSize(N);
    let delta:i64 = (modulus_q.clone() as i64)/(modulus_p.clone() as i64);

    let mut rng = thread_rng();
    let glwe_poly_list = generate_glwe_secret_key(polynomial_size, glwe_size);
    //In general even a secure key gen can generate such bad keys with small probability
    let trial_key = toy_binary_randomness(N,k);
    //will panic when the hamming weight of the glwe_sec_key_list is low! 
    assert!(hamming_weight(trial_key.clone())< hamming_weight(glwe_poly_list.clone().into_container()));

    let db2:i64 =(delta/2);
    let mut encoded_msg_vec:Vec<i64> = plaintext.iter().map(|&x| x*delta%modulus_q).collect(); 
    let mut encoded_msg = Polynomial::from_container(convert_Vi64_to_Vu64(encoded_msg_vec.clone()));

    println!("Plain text message :M=  {:?}",plaintext.clone());
    println!("encoded message : delta* M= {:?}",encoded_msg_vec.clone());
    println!("glwe secret key list= {:?}",glwe_poly_list.clone());

    let mut mask_vector:Vec<i64> = Vec::new();
    for i in 0..=N*k-1 {
        mask_vector.push(rng.gen_range(-modulus_q..=modulus_q-1));
    }
    println!("Mask vector list = {:?}",mask_vector.clone());
    let mask_poly_list = PolynomialList::from_container(convert_Vi64_to_Vu64(mask_vector.clone()),polynomial_size);
 
    let mut error_vec:Vec<i64> =Vec::new();
    for i in 0..= N-1{
         error_vec.push(rng.gen_range(-db2+1..db2));
    } 
    println!("Error vec {:?}",error_vec.clone());
    let mut error_poly =  Polynomial::from_container(convert_Vi64_to_Vu64(error_vec.clone()));

    let mut Body = Polynomial::new(0u64,polynomial_size);
    polynomial_wrapping_add_multisum_assign(&mut Body, &mask_poly_list.clone(), &glwe_poly_list.clone());
    polynomial_wrapping_add_assign(&mut Body,&encoded_msg);
    polynomial_wrapping_add_assign(&mut Body,&error_poly);

    let mut temp_body = convert_Vu64_to_Vi64(Body.clone().into_container());
        println!("Body {:?}",modular_red_vec(temp_body, modulus_q));
    let mut cipher_text:Vec<u64> = mask_poly_list.clone().into_container();
    for x in Body.clone().into_container(){
        cipher_text.push(x);
    }
    let mut cipher_text_poly = PolynomialList::from_container(cipher_text.clone(), polynomial_size);
    (cipher_text_poly,glwe_poly_list)        
}

/// Given the cipher text, secrte key and GLWE parameters, decrypts the given cipher text and outputs the plain text
pub fn decrypt_glwe(cipher_text_poly:PolynomialList<Vec<u64>>,glwe_poly_list:PolynomialList<Vec<u64>>, modulus_p:i64, modulus_q: i64, N:usize, k:usize) -> Vec<i64>{
    let polynomial_size = cipher_text_poly.polynomial_size();
    let mut cipher_text:Vec<u64> = cipher_text_poly.clone().into_container();
    let mut mask_poly_list= PolynomialList::from_container(cipher_text[0..=N*k-1].to_vec(),polynomial_size);
    let mut body_poly= Polynomial::from_container(cipher_text[N*k..=N*k+N-1].to_vec());
    let mut result = Polynomial::new(0u64, polynomial_size);

    polynomial_wrapping_add_multisum_assign(&mut result, &mask_poly_list.clone(), &glwe_poly_list.clone());
    polynomial_wrapping_sub_assign(&mut body_poly, &result);    
    let result_unmod = convert_Vu64_to_Vi64(body_poly.clone().into_container());
    let delta:i64 = (modulus_q.clone() as i64)/(modulus_p.clone() as i64);
    let mod_result:Vec<i64> =  result_unmod.iter().map(|&x|div_by_delta(x, delta)).collect();
    println!("Recovered plain text After rounding {:?}",mod_result.clone());
    mod_result
}

pub fn toy_binary_randomness(N: usize,k:usize) -> Vec<u64>{
    let mut rng = rand::thread_rng();
    let mut secret_key = vec![0u64;N*k];
    for i in 0..=k-1{
        secret_key[rng.gen_range(i*N..=(i+1)*N-1)]+=1u64;
    }
    secret_key
}

pub fn hamming_weight(input_1:Vec<u64>)->usize {
    let mut temp =0;
    for i in 0..=input_1.len()-1{
        if input_1[i]==1 {
            temp+=1
        } else if input_1[i]>1 {
             panic!("Not a binary vector")
        }
    }
    temp
}

