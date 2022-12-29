#ifndef LBCRYPTO_CRYPTO_BFVRNSSFDK_C
#define LBCRYPTO_CRYPTO_BFVRNSSFDK_C

#include <fstream>
#include <iostream>
#include "scheme/bfvrns-sfdk/bfvrns-sfdk.h"
#include "cryptocontext-sfdk.h"
#include "utils.h"
#include "utils/debug.h"

namespace lbcrypto {

template <class Element>
LPCryptoParametersBFVrnssfdk<Element>::LPCryptoParametersBFVrnssfdk()
    : LPCryptoParametersBFVrns<Element>() {
    m_k = 0;
    m_base = 2;
    }

template <class Element>
LPCryptoParametersBFVrnssfdk<Element>::LPCryptoParametersBFVrnssfdk(
    const LPCryptoParametersBFVrnssfdk &rhs)
    : LPCryptoParametersBFVrns<Element>(rhs) {
  m_base = rhs.GetBase();
  m_k = rhs.GetK();
}

template <class Element>
LPCryptoParametersBFVrnssfdk<Element>::LPCryptoParametersBFVrnssfdk(
    shared_ptr<ParmType> params, const PlaintextModulus &plaintextModulus,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth, usint base,
    bool VerifyNormFlag)
    : LPCryptoParametersBFVrns<Element>(
          params,
          EncodingParams(
              std::make_shared<EncodingParamsImpl>(plaintextModulus)),
          distributionParameter, assuranceMeasure, securityLevel, relinWindow,
          mode, depth, maxDepth),
      m_base(base),
      VerifyNorm(VerifyNormFlag) {

  const typename Element::Integer &q = params->GetModulus();
  size_t n = params->GetRingDimension();
  usint nBits = floor(log2(q.ConvertToDouble() - 1.0) + 1.0);
  m_k = ceil(nBits / log2(base));
  double c = (base + 1) * SIGMA;
  double s = SPECTRAL_BOUND(n, m_k, base);
  if (sqrt(s * s - c * c) <= KARNEY_THRESHOLD)
    m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
  else
    m_dggLargeSigma = this->GetDiscreteGaussianGenerator();
}


template <class Element>
LPCryptoParametersBFVrnssfdk<Element>::LPCryptoParametersBFVrnssfdk(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth, usint base,
    bool VerifyNormFlag)
    : LPCryptoParametersBFVrns<Element>(
          params, encodingParams, distributionParameter, assuranceMeasure,
          securityLevel, relinWindow, mode, depth, maxDepth),
      m_base(base),
      VerifyNorm(VerifyNormFlag) {

  const typename Element::Integer &q = params->GetModulus();
  size_t n = params->GetRingDimension();
  usint nBits = floor(log2(q.ConvertToDouble() - 1.0) + 1.0);
  m_k = ceil(nBits / log2(base));
  double c = (base + 1) * SIGMA;
  double s = SPECTRAL_BOUND(n, m_k, base);
  if (sqrt(s * s - c * c) <= KARNEY_THRESHOLD)
    m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
  else
    m_dggLargeSigma = this->GetDiscreteGaussianGenerator();
}

template <class Element>
LPCryptoParametersBFVrnssfdk<Element>::LPCryptoParametersBFVrnssfdk(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure,
    SecurityLevel securityLevel, usint relinWindow, MODE mode, int depth,
    int maxDepth, usint base, bool VerifyNormFlag)
    : LPCryptoParametersBFVrns<Element>(
          params, encodingParams, distributionParameter, assuranceMeasure,
          securityLevel, relinWindow, mode, depth, maxDepth),
      m_base(base),
      VerifyNorm(VerifyNormFlag) {
  const typename Element::Integer &q = params->GetModulus();
  size_t n = params->GetRingDimension();
  usint nBits = floor(log2(q.ConvertToDouble() - 1.0) + 1.0);
  m_k = ceil(nBits / log2(base));
  double c = (base + 1) * SIGMA;
  double s = SPECTRAL_BOUND(n, m_k, base);
  if (sqrt(s * s - c * c) <= KARNEY_THRESHOLD)
    m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
  else
    m_dggLargeSigma = this->GetDiscreteGaussianGenerator();
  ;
}


template <class Element>
LPKeyTupple<Element> LPAlgorithmSFDKBFVrns<Element>::KeyGen(CryptoContextSFDK<Element> cc) {

  //auto functionDecryptionKeyGen = static_cast<SFDKDecKeyGen<Element> *>(sfdkg);
  LPKeyTuppleImpl<Element> kp(std::make_shared<LPLargePublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc),
                        std::make_shared<LPKeyCipherGenKeyImpl<Element>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrnssfdk<Element>>(
         cc->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  usint base = cryptoParams->GetBase();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  auto stddev = dgg.GetStd();


  // Generate trapdoor based using parameters and
  std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> keyPair =
      RLWETrapdoorUtility<Element>::TrapdoorGen(elementParams, stddev, base);
  usint k = keyPair.first.GetData()[0].size();
  cryptoParams->SetK(k);
  //elementParams->SetK(keyPair.first.GetData()[0].size());
    // Format of vectors are changed to prevent complications in calculations
  keyPair.second.m_e.SetFormat(Format::EVALUATION);
  keyPair.second.m_r.SetFormat(Format::EVALUATION);


  Matrix<Element> &a = keyPair.first;

  a.SetFormat(Format::EVALUATION);
  // Generate the secret key
  Element s;

  // Done in two steps not to use a random polynomial from a pre-computed pool
  // Supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases


  if (cryptoParams->GetMode() == RLWE) {
    s = Element(dgg, elementParams, Format::COEFFICIENT);
  } else {
    s = Element(tug, elementParams, Format::COEFFICIENT, 0);
  }
  s.SetFormat(Format::EVALUATION);

  kp.secretKey->SetPrivateElement(s);


  auto zero_alloc = DCRTPoly::Allocator(elementParams, EVALUATION);
  auto gaussian_alloc = DCRTPoly::MakeDiscreteGaussianCoefficientAllocator(
      elementParams, Format::COEFFICIENT, dgg.GetStd());
  // Done in two steps not to use a discrete Gaussian polynomial from a
  // pre-computed pool
  Matrix<Element> e(zero_alloc,1,k,gaussian_alloc);
  //Element e(dgg, elementParams, Format::COEFFICIENT,elementParams->GetK());
  e.SetFormat(Format::EVALUATION);

  Matrix<Element> b(zero_alloc,1,k);
  //Element b(elementParams, Format::EVALUATION, true, elementParams->GetK());
  b -= e;
  b -= (a * s);

  kp.publicKey->SetLargePublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetLargePublicElementAtIndex(1, std::move(a));


  // Signing key will contain public key matrix of the trapdoor and the trapdoor
  // matrices
  //functionDecryptionKeyGen->SetSFDKDecKeyGen(
  //    std::make_shared<RLWETrapdoorPair<typename Element::PType>>(keyPair.second));
  kp.cipherKeyGen->SetKeyTag(kp.secretKey->GetKeyTag());
  kp.cipherKeyGen->SetPrivateElement(std::make_shared<RLWETrapdoorPair<Element>>(keyPair.second));

  return kp;
}

template <class Element>
LPKeyCipher<Element> LPAlgorithmSFDKBFVrns<Element>::GenDecKeyFor(Ciphertext<Element> &cipherText, LPKeyCipherGenKey<Element> keyGen, LPXPublicKey<Element> publicKey) {
    const std::vector<Element> &cipherTextElements = cipherText->GetElements();
    if(cipherTextElements.size() != 2) {
      PALISADE_THROW(config_error,
                     "Specific DecKey is only defined for ciphertexts of size 2"
                     "Please relinearize before");
    }
    // if(cipherTextElements[1].GetNumOfElements() != 1) {
    //   PALISADE_THROW(config_error,
    //                  "Specific DecKey is only defined for single polynomial ciphertexts");
    // }
    const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrnssfdk<Element>>(
         publicKey->GetCryptoParameters());
    auto params = cryptoParams->GetElementParams();
    size_t n = params->GetRingDimension();
    size_t k = cryptoParams->GetK();
    size_t base = cryptoParams->GetBase();

    EncodingParams ep(
      std::make_shared<EncodingParamsImpl>(PlaintextModulus(512)));

    DCRTPoly u = cipherTextElements[1];
    u.SetFormat(Format::EVALUATION);

    // Getting the trapdoor, its public matrix, perturbation matrix and gaussian
    // generator to use in sampling
    auto A = publicKey->GetLargePublicElements()[1];
    auto zero_alloc = DCRTPoly::Allocator(params, EVALUATION);

    DggType dgg = cryptoParams->GetDiscreteGaussianGenerator();

    DggType &dggLargeSigma =
      cryptoParams->GetDiscreteGaussianGeneratorLargeSigma();

    Matrix<Element> zHat = RLWETrapdoorUtility<Element>::GaussSamp(
      n, k-2, A, *keyGen->GetPrivateElement(), u, dgg, dggLargeSigma, base);

    return std::make_shared<LPKeyCipherImpl<Element>>(std::make_shared<Matrix<Element>>(zHat), publicKey);
  }

template <class Element>
DecryptResult LPAlgorithmSFDKBFVrns<Element>::Decode(Element &b,  NativePoly *plaintext, shared_ptr<LPCryptoParametersBFVrns<Element>>  cryptoParamsBFVrns) {


  const shared_ptr<typename Element::Params> elementParams =
      cryptoParamsBFVrns->GetElementParams();
    
  b.SetFormat(Format::COEFFICIENT);

  auto &t = cryptoParamsBFVrns->GetPlaintextModulus();

  const std::vector<double> &tQHatInvModqDivqFrac =
      cryptoParamsBFVrns->GettQHatInvModqDivqFrac();
  const std::vector<double> &tQHatInvModqBDivqFrac =
      cryptoParamsBFVrns->GettQHatInvModqBDivqFrac();
  const std::vector<NativeInteger> &tQHatInvModqDivqModt =
      cryptoParamsBFVrns->GettQHatInvModqDivqModt();
  const std::vector<NativeInteger> &tQHatInvModqDivqModtPrecon =
      cryptoParamsBFVrns->GettQHatInvModqDivqModtPrecon();
  const std::vector<NativeInteger> &tQHatInvModqBDivqModt =
      cryptoParamsBFVrns->GettQHatInvModqBDivqModt();
  const std::vector<NativeInteger> &tQHatInvModqBDivqModtPrecon =
      cryptoParamsBFVrns->GettQHatInvModqBDivqModtPrecon();

  // this is the resulting vector of coefficients;
  *plaintext =
      b.ScaleAndRound(t, tQHatInvModqDivqModt, tQHatInvModqDivqModtPrecon,
                      tQHatInvModqBDivqModt, tQHatInvModqBDivqModtPrecon,
                      tQHatInvModqDivqFrac, tQHatInvModqBDivqFrac);

  // std::cout << "Decryption time (internal): " << TOC_US(t_total) << " us" <<
  // std::endl;

  return DecryptResult(plaintext->GetLength());
}

template <class Element>
DecryptResult LPAlgorithmSFDKBFVrns<Element>::DecryptSfdk(Ciphertext<Element> &ciphertext, LPKeyCipher<Element> decKey, LPXPublicKey<Element> pubKey, Plaintext *plaintext) {

  
  const std::vector<Matrix<Element>> &pubKeyElements = pubKey->GetLargePublicElements();
  Matrix<Element> b = pubKeyElements[0];

  const std::vector<Element> &c = ciphertext->GetElements();

  Element r = c[0];
  r.SetFormat(Format::EVALUATION);
  b.SetFormat(Format::EVALUATION);
  decKey->getPrivateElement()->SetFormat(Format::EVALUATION);
  r -= SdfkUtils<Element>::dotProd(b,*decKey->getPrivateElement());


  // this is the resulting vector of coefficients;

  auto vp = std::make_shared<typename NativePoly::Params>(
      ciphertext->GetElements()[0].GetParams()->GetCyclotomicOrder(), decKey->GetCryptoContext()->GetEncodingParams()->GetPlaintextModulus(), 1);
  Plaintext decrypted = PlaintextFactory::MakePlaintext(ciphertext->GetEncodingType(), vp, decKey->GetCryptoContext()->GetEncodingParams());

  DecryptResult result = Decode(r, &decrypted->GetElement<NativePoly>(),
      std::static_pointer_cast<LPCryptoParametersBFVrns<Element>>(decKey->GetCryptoParameters()));

  // std::cout << "Decryption time (internal): " << TOC_US(t_total) << " us" <<
  // std::endl;
  if (result.isValid == false) return result;
  decrypted->Decode();
  *plaintext = std::move(decrypted);

  return result;
}

template <class Element>
void LPAlgorithmSFDKBFVrns<Element>::PreparePSM(LPPrivateKey<Element> secretKey, uint maxsize, CryptoContext<Element> cryptoContext) {
  auto n = cryptoContext->GetRingDimension();
  if(maxsize > n) {
    maxsize = n;
  }
  std::vector<int32_t> keys4shifts  = {};
  uint i;

  for(i=1; i<maxsize; i <<= 1) {
    keys4shifts.push_back(i);
    keys4shifts.push_back(-i);
  }
  keys4shifts.push_back(i);
  keys4shifts.push_back(-i);
  cryptoContext->EvalAtIndexKeyGen(secretKey, keys4shifts);
}

template <class Element>
Ciphertext<Element> LPAlgorithmSFDKBFVrns<Element>::PrivateSetMembership(Ciphertext<Element> ciphertext, uint start, uint size,
 CryptoContext<Element> cryptoContext, LPPrivateKey<Element> secretKey) {
  auto n = cryptoContext->GetRingDimension();
  uint comp_size = size > n ? n : size;

  // Copy ciphertext to every slot to be compared
  // The number of rot/add is ceil(log(size)) where size is the number of elements in the Private Set
  uint rot ;

  Ciphertext<Element> filled_ciphertext = nullptr;
  for(rot =1;rot <= comp_size; rot = rot << 1) {
    if((size&rot) != 0) {
      filled_ciphertext = filled_ciphertext==nullptr ? ciphertext : cryptoContext->EvalAdd(ciphertext,cryptoContext->EvalAtIndex(filled_ciphertext, -rot));
    }
    ciphertext = cryptoContext->EvalAdd(ciphertext,cryptoContext->EvalAtIndex(ciphertext, -rot));
  }

  for(uint t=0; t <= size/n; t++) {
    std::vector<int64_t> plainvector(t==(size/n)? size - t*n : n) ; // vector with 100 ints.
    std::iota (std::begin(plainvector), std::end(plainvector), start + t*n); // Fill with 0, 1, ..., 99.
    Plaintext testset = cryptoContext->MakePackedPlaintext(plainvector);
    // Subtract every element in the set from one of the copies of the plaintext.
    // The slot with an equal value becames zero, all the others are different from zero.
    ciphertext = t==0 ? 
                 cryptoContext->EvalSub(filled_ciphertext, testset) : 
                 cryptoContext->EvalMult(ciphertext,cryptoContext->EvalSub(filled_ciphertext, testset));

  }

  // Caclulate the x^(p-1) mod p, where x is each of the slot values.
  // The slot with a zero value remains zero, all the other became 1 by the Fermat Little Theorem
  auto p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();

  ciphertext = cryptoContext->EvalMult(ciphertext,ciphertext);

  Ciphertext<Element> result = nullptr;
  for(uint mask =2; mask < p; mask <<= 1) {
    if((p & mask) != 0 ) {
      result = result == nullptr ? ciphertext :cryptoContext->EvalMult(result,ciphertext);
    }
    ciphertext = cryptoContext->EvalMult(ciphertext,ciphertext);
  }

  // Add every element in the vector, by adding half of the vetor slots with the other half for ceil(log(size)) times
  for(rot = rot/2; rot>0; rot=rot/2 ) {
    result = cryptoContext->EvalAdd(result,cryptoContext->EvalAtIndex(result, rot));
  }

  // Use a mask to clean all other slot elements besides the first
  std::vector<int64_t> mask_2(1, 1);
  Plaintext mask2 = cryptoContext->MakePackedPlaintext(mask_2); 
  result = cryptoContext->EvalMult(result,mask2);

  // Subtracts the size of the vector 
  Plaintext _size = cryptoContext->MakePackedPlaintext({size>n?n-1:size-1});
  result = cryptoContext->EvalSub(result,_size);
  
  // Returns 0 if ciphertext is in the set or 1 if it is not
  return result;

}


template <class Element>
Ciphertext<Element> LPAlgorithmSFDKBFVrns<Element>::PrivateSetMembership(Ciphertext<Element> ciphertext, std::vector<int64_t> &_testset,
 CryptoContext<Element> cryptoContext, LPPrivateKey<Element> secretKey) {

  Plaintext testset = cryptoContext->MakePackedPlaintext(_testset);
  uint size = _testset.size();
  // Copy ciphertext to every slot to be compared
  // The number of rot/add is ceil(log(size)) where size is the number of elements in the Private Set
  uint rot ;
  bool first = true;
  Ciphertext<Element> result;
  for(rot =1;rot <= size; rot = rot << 1) {
    if((size&rot) != 0) {
      result = first ? ciphertext : cryptoContext->EvalAdd(ciphertext,cryptoContext->EvalAtIndex(result, -rot));
      first = false;
    }
    ciphertext = cryptoContext->EvalAdd(ciphertext,cryptoContext->EvalAtIndex(ciphertext, -rot));
  }

  // Subtract every element in the provate set from one of the copies of the plaintext.
  // The slot with an equal value becames zero, all the others are different from zero.
  ciphertext =cryptoContext->EvalSub(result, testset);

  // Caclulate the x^(p-1) mod p, where x is each of the slot values.
  // The slot with a zero value remains zero, all the other became 1 by the Fermat Little Theorem
  auto p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();

  ciphertext = cryptoContext->EvalMult(ciphertext,ciphertext);
  first = true;

  for(uint mask =2; mask < p; mask <<= 1) {
    if((p & mask) != 0 ) {
      if(first) {
        first = false;
        result = ciphertext;
      } else {
        result = cryptoContext->EvalMult(result,ciphertext);
      }
    }
    ciphertext = cryptoContext->EvalMult(ciphertext,ciphertext);
  }

  // Creates a mask to clean the extra values in the vector, beyond the size of the set
  // Multiplies the mask by the ciphertext
  //std::vector<int64_t> mask_1(size, 1);
  //Plaintext mask1 = cryptoContext->MakePackedPlaintext(mask_1); 
  //result = cryptoContext->EvalMult(result,mask1);


  // Add every element in the vector, by adding half of the vetor slots with the other half for ceil(log(size)) times
  for(rot = rot/2; rot>0; rot=rot/2 ) {
    result = cryptoContext->EvalAdd(result,cryptoContext->EvalAtIndex(result, rot));
  }

  // Use a mask to clean all other slot elements besides the first
  std::vector<int64_t> mask_2(1, 1);
  Plaintext mask2 = cryptoContext->MakePackedPlaintext(mask_2); 
  result = cryptoContext->EvalMult(result,mask2);

  // Subtracts the size of the vector 
  Plaintext _size = cryptoContext->MakePackedPlaintext({size-1});
  result = cryptoContext->EvalSub(result,_size);
  
  // Returns 0 if ciphertext is in the set or 1 if it is not
  return result;
}

// Enable for LPPublicKeyEncryptionSchemeBFVrns
template <class Element>
void LPPublicKeyEncryptionSchemeBFVrnssfdk<Element>::Enable(
    PKESchemeFeature feature) {
  switch (feature) {
    case ENCRYPTION:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFVrnssfdk<Element>>();
            //std::make_shared<LPAlgorithmBFVrns<Element>>();
      break;
    case SHE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFVrnssfdk<Element>>();
            //std::make_shared<LPAlgorithmBFVrns<Element>>();
      if (this->m_algorithmSHE == nullptr)
        this->m_algorithmSHE =
            std::make_shared<LPAlgorithmSHEBFVrns<Element>>();
      break;
    case PRE:
      PALISADE_THROW(not_implemented_error,
                     "PRE feature not supported for BFVrnssfdk scheme");
      break;
    case MULTIPARTY:
      PALISADE_THROW(not_implemented_error,
                     "Muliparty feature not supported for BFVrnssfdk scheme");
      break;
    case FHE:
      PALISADE_THROW(not_implemented_error,
                     "FHE feature not supported for BFVrns scheme");
    case LEVELEDSHE:
      PALISADE_THROW(not_implemented_error,
                     "LEVELEDSHE feature not supported for BFVrns scheme");
    case ADVANCEDSHE:
      PALISADE_THROW(not_implemented_error,
                     "ADVANCEDSHE feature not supported for BFVrns scheme");
  }
}

template <class Element>
void LPPublicKeyEncryptionSchemeBFVrnssfdk<Element>::Enable(usint mask) {
  LPPublicKeyEncryptionScheme<Element>::Enable(mask);
  if (mask & SFDK && this->m_algorithmSFDK == nullptr) {
    this->m_algorithmSFDK =
      std::make_shared<LPAlgorithmSFDKBFVrns<Element>>();
  }
}

template <class Element>
usint LPPublicKeyEncryptionSchemeBFVrnssfdk<Element>::GetEnabled() const {
  usint flag = LPPublicKeyEncryptionScheme<Element>::GetEnabled() ;

  if (m_algorithmSFDK != nullptr) flag |= SFDK;
  return flag;
}

template <class Element>
LPPublicKeyEncryptionSchemeBFVrnssfdk<Element>::LPPublicKeyEncryptionSchemeBFVrnssfdk()
    : LPPublicKeyEncryptionSchemeSFDK<Element>() {
  this->m_algorithmParamsGen =
      std::make_shared<LPAlgorithmParamsGenBFVrns<Element>>();
}


}  // namespace lbcrypto

#endif
