

#ifndef SRC_SFDK_CRYPTOCONTEXT_H_
#define SRC_SFDK_CRYPTOCONTEXT_H_


#include "pke/cryptocontext.h"
#include "pubkeylp-sfdk.h"

#define SFDK 0x80

namespace lbcrypto {

template <typename Element>
class CryptoContextFactorySFDK;

template <typename Element>
class CryptoContextSFDKImpl;

template <typename Element>
using CryptoContextSFDK = shared_ptr<CryptoContextSFDKImpl<Element>>;


template <class Element>
class LPPublicKeyEncryptionSchemeSFDK
    : public LPPublicKeyEncryptionSchemeBFVrns<Element> {

 public:
  LPPublicKeyEncryptionSchemeSFDK() {}

  virtual LPKeyTupple<Element> KeyGenSfdk(CryptoContextSFDK<Element> cc) {
    PALISADE_THROW(not_implemented_error,"Not Implemented");
  };

  virtual LPKeyCipher<Element> GenDecKeyFor(Ciphertext<Element> &cipherText, LPKeyCipherGenKey<Element> keyGen, LPXPublicKey<Element> publicKey) {
    PALISADE_THROW(not_implemented_error,"Not Implemented");
  }

  virtual DecryptResult DecryptSFDK(Ciphertext<Element> &ciphertext, LPKeyCipher<Element> &decKey, LPXPublicKey<Element> publicKey, Plaintext *plaintext) {
    PALISADE_THROW(not_implemented_error,"Not Implemented");
  }

  virtual void PreparePSM(LPPrivateKey<Element> secretKey, uint maxsize, CryptoContext<Element> cryptoContext)  {
    PALISADE_THROW(not_implemented_error,"Not Implemented");
  }


  virtual Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> &ciphertext, std::vector<int64_t> &testset, CryptoContext<Element> cryptoContext, LPPrivateKey<Element> secretKey){
    PALISADE_THROW(not_implemented_error,"Not Implemented");
  }

  virtual Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> &ciphertext, uint start, uint size, CryptoContext<Element> cryptoContext, LPPrivateKey<Element> secretKey){
    PALISADE_THROW(not_implemented_error,"Not Implemented");
  }

};

template <typename Element>
class CryptoContextSFDKImpl : public CryptoContextImpl<Element> {

  friend class CryptoContextFactorySFDK<Element>;

  const std::shared_ptr<LPPublicKeyEncryptionSchemeSFDK<Element>>
  GetMyEncryptionAlgorithm() const {
    return std::dynamic_pointer_cast<LPPublicKeyEncryptionSchemeSFDK<Element>>(CryptoContextImpl<Element>::scheme);
  }
public: 


  LPKeyCipher<Element> GenDecKeyFor(Ciphertext<Element> &cipherText, LPKeyCipherGenKey<Element> keyGen, LPXPublicKey<Element> publicKey) {
    auto r = GetMyEncryptionAlgorithm()->GenDecKeyFor(cipherText, keyGen, publicKey);
    return r;    
  }

  LPKeyTupple<Element> KeyGenSfdk() {
    auto context = CryptoContextFactory<Element>::GetContextForPointer(this);
    auto r = GetMyEncryptionAlgorithm()->KeyGenSfdk(std::dynamic_pointer_cast<CryptoContextSFDKImpl<Element>>(context));
    return r;
  }

  DecryptResult DecryptSfdk(Ciphertext<Element> &ciphertext, LPKeyCipher<Element> decKey, LPXPublicKey<Element> publicKey, Plaintext *plaintext) {
    auto r = GetMyEncryptionAlgorithm()->DecryptSFDK(ciphertext, decKey, publicKey, plaintext);
    return r;  
  }

  void PreparePSM(LPPrivateKey<Element> secretKey, uint maxsize) {
    auto context = CryptoContextFactory<Element>::GetContextForPointer(this);
    GetMyEncryptionAlgorithm()->PreparePSM(secretKey, maxsize, context);    
  }

  Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> &ciphertext, std::vector<int64_t> &testset, LPPrivateKey<Element> secretKey) {
    auto context = CryptoContextFactory<Element>::GetContextForPointer(this);
    auto r = GetMyEncryptionAlgorithm()->PrivateSetMembership(ciphertext, testset, context, secretKey);
    return r;  
  }

  Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> &ciphertext, uint start, uint size, LPPrivateKey<Element> secretKey) {
    auto context = CryptoContextFactory<Element>::GetContextForPointer(this);
    auto r = GetMyEncryptionAlgorithm()->PrivateSetMembership(ciphertext, start, size, context, secretKey);
    return r;  
  }

  CryptoContextSFDKImpl(LPCryptoParameters<Element>* params = nullptr,
                    LPPublicKeyEncryptionScheme<Element>* scheme = nullptr,
                    const string& schemeId = "Not") : CryptoContextImpl<Element>(params,scheme,schemeId) {
  }

  CryptoContextSFDKImpl(shared_ptr<LPCryptoParameters<Element>> params,
                    shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme,
                    const string& schemeId = "Not") : CryptoContextImpl<Element>(params,scheme,schemeId) {
  }

  /**
   * Copy constructor
   * @param c - source
   */
  CryptoContextSFDKImpl(const CryptoContextImpl<Element>& c) : CryptoContextImpl<Element>(c) {
  }

 
};


/**
 * @brief CryptoContextFactorySFDK
 *
 * A class that contains static methods to generate new SAFDK crypto contexts from
 * user parameters
 *
 */
template <typename Element>
class CryptoContextFactorySFDK : public CryptoContextFactory<Element> {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;

  public:

  static CryptoContextSFDK<Element> GetContext(
    shared_ptr<LPCryptoParameters<Element>> params,
    shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme,
    const string& schemeId = "Not");

  static CryptoContextSFDK<Element> genCryptoContextBFVrnsSFDK(
      const PlaintextModulus plaintextModulus, float securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0, usint base = 2, bool VerifyNorm = false);

  static CryptoContextSFDK<Element> genCryptoContextBFVrnsSFDK(
      const PlaintextModulus plaintextModulus, SecurityLevel securityLevel,
      float dist, unsigned int numAdds, unsigned int numMults,
      unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
      uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0, usint base = 2, bool VerifyNorm = false);

  static CryptoContextSFDK<Element> genCryptoContextBFVrnsSFDK(
      EncodingParams encodingParams, float securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0, usint base = 2, bool VerifyNorm = false);

  static CryptoContextSFDK<Element> genCryptoContextBFVrnsSFDK(
      EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0, usint base = 2, bool VerifyNorm = false);

};





}  // namespace lbcrypto

#endif /* SRC_SFDK_CRYPTOCONTEXT_H_ */
