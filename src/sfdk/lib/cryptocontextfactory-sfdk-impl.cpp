#include "scheme/bfvrns-sfdk/bfvrns-sfdk.h"

#include "cryptocontext-sfdk.h"
#include "core/utils/serial.h"

namespace lbcrypto {

template <typename Element>
vector<CryptoContext<Element>> CryptoContextFactory<Element>::AllContexts;


// factory methods for the different schemes

template <typename T>
CryptoContextSFDK<T> CryptoContextFactorySFDK<T>::GetContext(
    shared_ptr<LPCryptoParameters<T>> params,
    shared_ptr<LPPublicKeyEncryptionScheme<T>> scheme,
    const string& schemeId) {
  for (CryptoContext<T> _cc : CryptoContextFactory<T>::AllContexts) {
    if (*_cc->GetEncryptionAlgorithm().get() == *scheme.get() &&
        *_cc->GetCryptoParameters().get() == *params.get()) {
        CryptoContextSFDK<T> cc = std::dynamic_pointer_cast<CryptoContextSFDKImpl<T>>(_cc);
        if(cc != nullptr) return cc;
    }
  }

  CryptoContextSFDK<T> cc(
      std::make_shared<CryptoContextSFDKImpl<T>>(params, scheme, schemeId));
  CryptoContextFactory<T>::AllContexts.push_back(cc);

  if (cc->GetEncodingParams()->GetPlaintextRootOfUnity() != 0) {
    PackedEncoding::SetParams(cc->GetCyclotomicOrder(),
                              cc->GetEncodingParams());
  }

  return cc;
}

template <typename T>
CryptoContextSFDK<T> CryptoContextFactorySFDK<T>::genCryptoContextBFVrnsSFDK(
    const PlaintextModulus plaintextModulus, float securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n, usint base, bool VerifyNorm ) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrns context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  //auto params = std::make_shared<LPCryptoParametersBFVrnssfdk<T>>();
  auto params = std::make_shared<LPCryptoParametersBFVrnssfdk<T>>(
       ep,
       EncodingParams(std::make_shared<EncodingParamsImpl>(plaintextModulus)),
       dist, 36.0, securityLevel, relinWindow, mode, 1, maxDepth, base, VerifyNorm);
  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFVrnssfdk<T>>();

  auto a = std::dynamic_pointer_cast<LPPublicKeyEncryptionScheme<T>>(scheme);
  
  a->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

  return GetContext(params, a);
}

template <typename T>
CryptoContextSFDK<T> CryptoContextFactorySFDK<T>::genCryptoContextBFVrnsSFDK(
      const PlaintextModulus plaintextModulus, SecurityLevel securityLevel,
      float dist, unsigned int numAdds, unsigned int numMults,
      unsigned int numKeyswitches, MODE mode, int maxDepth,
      uint32_t relinWindow, size_t dcrtBits, uint32_t n, usint base, bool VerifyNorm) {
  EncodingParams encodingParams(
      std::make_shared<EncodingParamsImpl>(plaintextModulus));

  return genCryptoContextBFVrnsSFDK(encodingParams, securityLevel, dist, numAdds,
                                numMults, numKeyswitches, mode, maxDepth,
                                relinWindow, dcrtBits, n, base, VerifyNorm);
}

template <typename T>
CryptoContextSFDK<T> CryptoContextFactorySFDK<T>::genCryptoContextBFVrnsSFDK(
    EncodingParams encodingParams, float securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n, usint base, bool VerifyNorm) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrns context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  //auto params = std::make_shared<LPCryptoParametersBFVrnssfdk<T>>();
  auto params = std::make_shared<LPCryptoParametersBFVrnssfdk<T>>(
       ep, encodingParams, dist, 36.0, securityLevel, relinWindow, mode, 1,
       maxDepth, base, VerifyNorm);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFVrnssfdk<T>>();

  auto a = std::dynamic_pointer_cast<LPPublicKeyEncryptionScheme<T>>(scheme);
  a->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

  return GetContext(params, a);
}

template <typename T>
CryptoContextSFDK<T> CryptoContextFactorySFDK<T>::genCryptoContextBFVrnsSFDK(
    EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n, usint base, bool VerifyNorm) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrns context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));
  //auto params = std::make_shared<LPCryptoParametersBFVrnssfdk<T>>();
   auto params = std::make_shared<LPCryptoParametersBFVrnssfdk<T>>(
       ep, encodingParams, dist, 36.0, securityLevel, relinWindow, mode, 1,
       maxDepth, base, VerifyNorm);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFVrnssfdk<T>>();

  auto a = std::dynamic_pointer_cast<LPPublicKeyEncryptionScheme<T>>(scheme);
  a->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

  return GetContext(params, a);
}


template class CryptoContextFactorySFDK<DCRTPoly>;

}  // namespace lbcrypto
