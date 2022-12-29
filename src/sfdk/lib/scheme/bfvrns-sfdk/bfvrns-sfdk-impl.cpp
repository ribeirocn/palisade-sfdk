
#include "cryptocontext-sfdk.h"
#include "bfvrns-sfdk.cpp"
#include "utils.h"


namespace lbcrypto {


template <class Element>
Ciphertext<Element> LPAlgorithmBFVrnssfdk<Element>::Encrypt(
    const LPPublicKey<Element> pubKey, Element ptxt) const {
  
  auto publicKey = std::dynamic_pointer_cast<LPLargePublicKeyImpl<Element>>(pubKey);
  if(publicKey == nullptr) {
    PALISADE_THROW(config_error, "Wrong PubKey type. Please, generate key for this context");
  }
  Ciphertext<Element> ciphertext(
      std::make_shared<CiphertextImpl<Element>>(publicKey));

  auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFVrnssfdk<Element>>(publicKey->GetCryptoParameters());

  auto elementParams = cryptoParams->GetElementParams();

  ptxt.SetFormat(Format::EVALUATION);

  const std::vector<NativeInteger> &delta = cryptoParams->GetDelta();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  TugType tug;

  Matrix<Element> p0 = publicKey->GetLargePublicElements().at(0);
  Matrix<Element> p1 = publicKey->GetLargePublicElements().at(1);

  //Matrix<Element> u;

  // Supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases
  //if (cryptoParams->GetMode() == RLWE)
    //u = Element(dgg, elementParams, Format::EVALUATION);  // old version
    //u = Element(dgg, elementParams, Format::EVALUATION, 0, p0.size());  // new version

  auto zero_alloc = DCRTPoly::Allocator(elementParams, EVALUATION);
  auto gaussian_alloc = DCRTPoly::MakeDiscreteGaussianCoefficientAllocator(
      elementParams, Format::COEFFICIENT, dgg.GetStd());
    //u = Matrix<Element>([&](){Element(dgg, elementParams, Format::EVALUATION);}, p0.GetData()[0].size(), 1);
  Matrix<Element> u(zero_alloc, p0.GetData()[0].size(), 1, gaussian_alloc);
  //else
    //u = Element(tug, elementParams, Format::EVALUATION); // old version
    //u = Element(tug, elementParams, Format::EVALUATION, 0, p0.size()); // new version
  //  u = Matrix([](){Element(tug, elementParams, Format::EVALUATION);}, p0[0].size(), 1);

  Element e1(dgg, elementParams, Format::EVALUATION);
  //Element e2(dgg, elementParams, Format::EVALUATION, p1.size()); // old version
  Element e2(dgg, elementParams, Format::EVALUATION); // new version

  Element c0(elementParams);
  Element c1(elementParams);

  p0.SetFormat(Format::EVALUATION);
  p1.SetFormat(Format::EVALUATION);
  u.SetFormat(Format::EVALUATION);

  c0 = SdfkUtils<Element>::dotProd(p0,u) + e1 + ptxt.Times(delta);

  c1 = SdfkUtils<Element>::dotProd(p1,u) + e2;

  ciphertext->SetElements({std::move(c0), std::move(c1)});

  return ciphertext;
} 


template class LPPublicKeyEncryptionSchemeBFVrnssfdk<lbcrypto::DCRTPoly>;
template class LPAlgorithmBFVrnssfdk<lbcrypto::DCRTPoly>;
template class LPAlgorithmSFDKBFVrns<lbcrypto::DCRTPoly>;
//template class LPPublicKeyEncryptionSchemeSFDK<lbcrypto::DCRTPoly>;

template class  LPCryptoParametersBFVrnssfdk<lbcrypto::DCRTPoly>;
//template class LPAlgorithmParamsGenBFVrnssfdk<lbcrypto::DCRTPoly>;
template class LPKeyCipherGenKeyImpl<lbcrypto::DCRTPoly>;
template class LPKeyCipherImpl<lbcrypto::DCRTPoly>;
template class LPKeyTuppleImpl<lbcrypto::DCRTPoly>;

}  // namespace lbcrypto
