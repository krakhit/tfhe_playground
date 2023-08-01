# FHE Research

So far:
Implementation of toy GLWE encryption/decryption for arbitrary N: Ring dimension, k+1 : GLWE dimension, q: cipher text modulus, p: Plain text modulus.
Error is drawn from uniform binary distribution. Supported data types: plain text in i64.

1. based on toy example in https://www.zama.ai/post/tfhe-deep-dive-part-1 : 
   1. GLWE encryption/decryption with uniform binary noise [X]
   2. GGSW encryption and decryption  []
   3. Reduction to RLWE/LWE []
   4. Guassian noise []
2. https://www.zama.ai/post/tfhe-deep-dive-part-2
   1. LWE arithmetic []
   2. RLWE arithmetic []
   3. GLWE arithmetic []
   4. GGSW arithmetic []
3. https://www.zama.ai/post/tfhe-deep-dive-part-3 []
4. https://www.zama.ai/post/tfhe-deep-dive-part-4 []