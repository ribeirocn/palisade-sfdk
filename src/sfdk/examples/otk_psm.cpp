
// @file  simple-integers.cpp - Simple example for BFVrns-sfdk (integer arithmetic).
// @author TPOC: carlos.ribeiro@tecnico.ulisboa.pt

// Modification of 
// @file  simple-integers.cpp - Simple example for BFVrns (integer arithmetic).
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "pke/palisade.h"
#include "lattice/elemparamfactory.h"
#include "cryptocontext-sfdk.h"
#include "math.h"
#include "scheme/bfvrns-sfdk/bfvrns-sfdk.h"

using namespace lbcrypto;


uint GetPSMDepth(uint p) {
    uint depth = 0;
    for(int mask=1;mask<=p; mask <<= 1){
      depth++;
      if((mask&p)>0) depth++;
    }
    return depth-2;
  }



CryptoContextSFDK<DCRTPoly> GenerateBFVrnsSFDKContext() {
  // Set the main parameters
  int plaintextModulus = 65537;;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = GetPSMDepth(plaintextModulus);

  // Instantiate the crypto context
  CryptoContextSFDK<DCRTPoly> cryptoContext =
      CryptoContextFactorySFDK<DCRTPoly>::genCryptoContextBFVrnsSFDK(
          plaintextModulus, securityLevel, sigma, 0, depth, 0, RLWE, 2, 0, 44, 0, 4194304);

  // Enable features that you wish to use
  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);
  cryptoContext->Enable(SFDK);

  return cryptoContext;
}
void printContext(CryptoContextSFDK<DCRTPoly> cryptoContext) {

  std::cout << "  Cyclotomic Order: " << cryptoContext->GetCyclotomicOrder() << std::endl;
  std::cout << "  Ring Dimension  : " << cryptoContext->GetRingDimension() << std::endl;
  std::cout << "  Log2 of Modulus : " << log2(cryptoContext->GetModulus().ConvertToDouble()) << std::endl;
  auto params = cryptoContext->GetCryptoParameters()->GetElementParams()->GetParams();
  std::cout << "  CRT Modulus     : " << params.size() << std::endl;
  unsigned long long maxp = 0;
  unsigned long long minp = ULLONG_MAX;
  for(auto par : params) {
    //std::cout << "Modulus: " << par->GetModulus() << std::endl;
    if(par->GetModulus() > maxp) maxp = par->GetModulus().ConvertToInt();
    if(par->GetModulus() < minp) minp = par->GetModulus().ConvertToInt();
  }
  std::cout << "  Max CRT Modulus : " << maxp << std::endl;
  std::cout << "  Min CRT Modulus : " << minp << std::endl;

  double sigma = std::static_pointer_cast<LPCryptoParametersRLWE<DCRTPoly>>(cryptoContext->GetCryptoParameters())->GetDistributionParameter();
  double alpha = std::static_pointer_cast<LPCryptoParametersRLWE<DCRTPoly>>(cryptoContext->GetCryptoParameters())->GetAssuranceMeasure();
  double Berr = sigma * sqrt(alpha);
  std::cout << "  Berr            : " << Berr << std::endl;
  std::cout << "  K               : " << std::static_pointer_cast<LPCryptoParametersBFVrnssfdk<DCRTPoly>>(cryptoContext->GetCryptoParameters())->GetK() << std::endl;

}


void PSM_Test(CryptoContextSFDK<DCRTPoly> cryptoContext, LPKeyTupple<DCRTPoly> keyPair ) {

  // Prepare PSM keys for biggest search set
  cryptoContext->PreparePSM(keyPair.secretKey, 2000);

  // Pattern to search
  std::vector<int64_t> vectorOfInts2 = {8};
  Plaintext pattern_plaintext = cryptoContext->MakePackedPlaintext(vectorOfInts2);
  auto pattern_ciphertext = cryptoContext->Encrypt(keyPair.publicKey, pattern_plaintext);

  // First set to search
  std::vector<int64_t> search_set = {1,2,3,4,5,6,7,8, 9};
  // Search and get an encrypted result 0 for found and 1 otherwise
  auto result1 = cryptoContext->PrivateSetMembership(pattern_ciphertext, search_set, keyPair.secretKey);

  // Search implicit set starting from 12 and ending in 2011
  auto result2 = cryptoContext->PrivateSetMembership(pattern_ciphertext, 12, 2000, keyPair.secretKey);
 
  // Generate Keys for specific results
  auto resultKey1 = cryptoContext->GenDecKeyFor(result1,  keyPair.cipherKeyGen, keyPair.publicKey);
  auto resultKey2 = cryptoContext->GenDecKeyFor(result2,  keyPair.cipherKeyGen, keyPair.publicKey);

  // Decrypt results print them
  Plaintext psmResult;
  cryptoContext->DecryptSfdk(result1, resultKey1, keyPair.publicKey, &psmResult);
  std::cout << "  PSM Result for first set: " << psmResult << std::endl;
  auto error = cryptoContext->GetDecryptionError(keyPair.secretKey, result1);
  std::cout << "Multiplication Decription Error Norm: " << error.Norm() << std::endl;
  cryptoContext->DecryptSfdk(result2, resultKey2, keyPair.publicKey, &psmResult);
  std::cout << "  PSM Result for second set: " << psmResult << std::endl;

}


void otk_simple_integers(CryptoContextSFDK<DCRTPoly> cryptoContext, LPKeyTupple<DCRTPoly> keyPair ) {
  // Generate the rotation evaluation keys
  //cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, {1, 2, -1, -2});
  cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, {1,-1});

  // Sample Program: Step 3: Encryption

  // First plaintext vector is encoded
  std::vector<int64_t> vectorOfInts1 = {1, 0, 3, 1, 0, 1, 2, 1};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  // Second plaintext vector is encoded
  std::vector<int64_t> vectorOfInts2 = {2, 1, 3, 2, 2, 1, 3, 1};
  Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

  // The encoded vectors are encrypted
  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
  auto ciphertext1a = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2a = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
  // Sample Program: Step 4: Evaluation

  // Homomorphic additions
  auto ciphertextAdd12 = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
  
  // Homomorphic multiplications
  auto ciphertextMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);
  auto ciphertextMul12a = cryptoContext->EvalMult(ciphertext1a, ciphertext2a);
  auto ciphertextSubMul = cryptoContext->EvalSub(ciphertextMul12, ciphertextMul12a);
  usint scale;
  auto ciphertextSponge = cryptoContext->GetZeroSpongeEncryption(keyPair.secretKey, keyPair.publicKey, ciphertextSubMul, scale);
  auto ciphertextSpongeScaled = cryptoContext->ScaleByBits(ciphertextSponge, scale);
  auto ciphertextSubMulReduced = cryptoContext->EvalAdd(ciphertextSubMul,ciphertextSpongeScaled);
  //


  // Homomorphic rotations
  auto ciphertextRot1 = cryptoContext->EvalAtIndex(ciphertext1, 1);

  // Sample Program: Step 5: Decryption

  // Decrypt the result of additions
  Plaintext plaintextAdd12;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd12,
                         &plaintextAdd12);

  auto np = plaintextAdd12->GetPackedValue();
  Plaintext plaintext2Add12 = cryptoContext->MakePackedPlaintext(np);  
  // Get error for decryption of addition
  auto error = cryptoContext->GetDecryptionError(keyPair.secretKey, ciphertextAdd12);
  std::cout << "Addition Decription Error Norm: " << error.Norm() << std::endl;

  // Decrypt the result of multiplications
  Plaintext plaintextMult12;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12,
                         &plaintextMult12);
  error = cryptoContext->GetDecryptionError(keyPair.secretKey, ciphertextMul12);
  std::cout << "Multiplication Decription Error Norm: " << error.Norm() << std::endl;


  // Decrypt the result of sub
  Plaintext plaintextSubMult;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextSubMul,
                         &plaintextSubMult);
  error = cryptoContext->GetDecryptionError(keyPair.secretKey, ciphertextSubMul);
  std::cout << "  Sutraction of Mult: " << plaintextSubMult << std::endl;
  std::cout << "Sutraction Decription Error Norm: " << error.Norm() << std::endl;


  // Decrypt the Sponge
  Plaintext plaintextSponge;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextSponge,
                         &plaintextSponge);
  error = cryptoContext->GetDecryptionError(keyPair.secretKey, ciphertextSponge);
  std::cout << "  Sponge of Sutraction of Mult: " << plaintextSponge << std::endl;
  std::cout << "Sponge Error Norm: " << error.Norm() << std::endl;

// Decrypt the SpongeScaled
  Plaintext plaintextSpongeScaled;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextSpongeScaled,
                         &plaintextSpongeScaled);
  error = cryptoContext->GetDecryptionError(keyPair.secretKey, ciphertextSpongeScaled);
  std::cout << "  Sponge Scaled of Sutraction of Mult: " << plaintextSpongeScaled << std::endl;
  std::cout << "Sponge Scaled Error Norm: " << error.Norm() << std::endl;

// Decrypt the SubMulReduced
  Plaintext plaintextSubMulReduced;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextSubMulReduced,
                         &plaintextSubMulReduced);
  error = cryptoContext->GetDecryptionError(keyPair.secretKey, ciphertextSubMulReduced);
  std::cout << "  SubMulReduced of Sutraction of Mult: " << plaintextSubMulReduced << std::endl;
  std::cout << "SubMulReduced Error Norm: " << error.Norm() << std::endl;

  // Sample Program: Step 5: OTK Decryption
 
  // OTK Decrypt of fresh encryption
  auto cipherKey = cryptoContext->GenDecKeyFor(ciphertextSubMulReduced,  keyPair.cipherKeyGen, keyPair.publicKey);
  Plaintext plaintextSFDKResult;
  cryptoContext->DecryptSfdk(ciphertextSubMulReduced, cipherKey, keyPair.publicKey, &plaintextSFDKResult);

  // OTK Decrypt of Addition
  cipherKey = cryptoContext->GenDecKeyFor(ciphertextAdd12,  keyPair.cipherKeyGen, keyPair.publicKey);
  Plaintext plaintextAddSFDKResult;
  cryptoContext->DecryptSfdk(ciphertextAdd12, cipherKey, keyPair.publicKey, &plaintextAddSFDKResult);

  // OTK Decrypt of Multiplication
  cipherKey = cryptoContext->GenDecKeyFor(ciphertextMul12,  keyPair.cipherKeyGen, keyPair.publicKey);
  Plaintext plaintextMulSFDKResult;
  cryptoContext->DecryptSfdk(ciphertextMul12, cipherKey, keyPair.publicKey, &plaintextMulSFDKResult);

  // OTK Decrypt of Rotation
  cipherKey = cryptoContext->GenDecKeyFor(ciphertextRot1,  keyPair.cipherKeyGen, keyPair.publicKey);
  Plaintext plaintextRotSFDKResult;
  cryptoContext->DecryptSfdk(ciphertextRot1, cipherKey, keyPair.publicKey, &plaintextRotSFDKResult);



  std::cout << "  Plaintext #1: " << plaintext1 << std::endl;
  std::cout << "  Plaintext #2: " << plaintext2 << std::endl;

  // Output results
  std::cout << "\n  Results of homomorphic computations" << std::endl;
  std::cout << "  #1 + #2: " << plaintextAdd12 << std::endl;
  std::cout << "  #1 * #2: " << plaintextMult12 << std::endl;
  //std::cout << "  Left rotation of #1 by 1: " << plaintextRot1 << std::endl;

  std::cout << "\n  Results with OTK decryption" << std::endl;
  std::cout << "  Decryption of #1: " << plaintextSFDKResult << std::endl;
  std::cout << "  Decryption of #1 + #2: " << plaintextAddSFDKResult << std::endl;
  std::cout << "  Left rotation of #1 by 1: " << plaintextRotSFDKResult << std::endl;

}

int main() {

  // Generate Context for SFDK
  std::cout << "Generating context ..." << std::flush;
  CryptoContextSFDK<DCRTPoly> cryptoContext = GenerateBFVrnsSFDKContext();

  // SFDK Key Generation
  LPKeyTupple<DCRTPoly> keyPair = cryptoContext->KeyGenSfdk();

  // Multiplication Key Generation
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);
  std::cout << " Done" << std::endl;
  printContext(cryptoContext);
  //std::cout << "PSM Test ..." << std::endl ;
  //PSM_Test(cryptoContext, keyPair);
  std::cout << "OTK Test ..." << std::endl ;
  otk_simple_integers(cryptoContext, keyPair);

  
  return 0;
}

