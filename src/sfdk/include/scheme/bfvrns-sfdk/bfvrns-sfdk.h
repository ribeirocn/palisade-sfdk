#ifndef LBCRYPTO_CRYPTO_BFVRNSSFDK_H
#define LBCRYPTO_CRYPTO_BFVRNSSFDK_H

#include <memory>
#include <string>
#include <vector>

#include "palisade.h"
#include "pke/scheme/bfvrns/bfvrns.h"
#include "cryptocontext-sfdk.h"



namespace lbcrypto {

/**
 * @brief This is the parameters class for the BFVrnssfdk encryption scheme.  This
 * scheme is also referred to as the FVrnssfdk scheme.
 *
 * @tparam Element a ring element type.
 */

template <class Element>
class LPCryptoParametersBFVrnssfdk : public LPCryptoParametersBFVrns<Element> {
    using ParmType = typename Element::Params;
 public:
  /**
   * Default constructor.
   */
  LPCryptoParametersBFVrnssfdk();
  LPCryptoParametersBFVrnssfdk(const LPCryptoParametersBFVrnssfdk& rhs);
  LPCryptoParametersBFVrnssfdk(shared_ptr<ParmType> params,
                           const PlaintextModulus& plaintextModulus,
                           float distributionParameter, float assuranceMeasure,
                           float securityLevel, usint relinWindow,
                           MODE mode = RLWE, int depth = 1, int maxDepth = 2,
                           usint base = 2, bool VerifyNormFlag = false);
  LPCryptoParametersBFVrnssfdk(shared_ptr<ParmType> params,
                           EncodingParams encodingParams,
                           float distributionParameter, float assuranceMeasure,
                           float securityLevel, usint relinWindow,
                           MODE mode = RLWE, int depth = 1, int maxDepth = 2,
                           usint base = 2, bool VerifyNormFlag = false);
  LPCryptoParametersBFVrnssfdk(shared_ptr<ParmType> params,
                           EncodingParams encodingParams,
                           float distributionParameter, float assuranceMeasure,
                           SecurityLevel securityLevel, usint relinWindow,
                           MODE mode = RLWE, int depth = 1, int maxDepth = 2,
                           usint base = 2, bool VerifyNormFlag = false);
  virtual ~LPCryptoParametersBFVrnssfdk() {}

  usint GetK() const {return m_k;}
  void SetK(usint k){m_k = k;}
  usint GetBase() const {return m_base;}
  void SetBase(usint base){m_base = base;}
  typename Element::DggType &GetDiscreteGaussianGeneratorLargeSigma() {return m_dggLargeSigma;}

  bool operator==(const LPCryptoParameters<Element>& rhs) const {
    const auto* el =
        dynamic_cast<const LPCryptoParametersBFVrnssfdk<Element>*>(&rhs);

    if (el == nullptr) return false;

    return el->GetK() == m_k && LPCryptoParametersBFVrns<Element>::operator==(rhs);
  }
  std::string SerializedObjectName() const { return "BFVrnssfdkSchemeParameters"; }
  static uint32_t SerializedVersion() { return 1; }

 protected:

  // Trapdoor base
  usint m_base;
  // Trapdoor length
  usint m_k;

  // Discrete Gaussian Generator for random number generation
  typename Element::DggType m_dgg;

  // Discrete Gaussian Generator with high distribution parameter for random
  // number generation
  typename Element::DggType m_dggLargeSigma;

  //flag for verifying norm of trapdoor
  bool VerifyNorm;
};


template <class Element>
class LPAlgorithmBFVrnssfdk : public LPAlgorithmBFVrns<Element> {
  // using IntType = typename Element::Integer;
  // using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  LPAlgorithmBFVrnssfdk() {}
  Ciphertext<Element> Encrypt(const LPPublicKey<Element> publicKey,
                              Element plaintext) const;
};


/**
 * @brief Encryption algorithm implementation for BFVrnssfdk for the basic public
 * key encrypt, decrypt and key generation methods for the BFVrnssfdk encryption
 * scheme.
 *
 * @tparam Element a ring element.
 */
template <class Element> 
class LPAlgorithmSFDKBFVrns {
  // using IntType = typename Element::Integer;
  using ParmType = typename Element::Params;
  using DggType = typename Element::DggType;
  using DugType = typename Element::DugType;
  using TugType = typename Element::TugType;

 public:
  LPAlgorithmSFDKBFVrns() {}
  LPKeyTupple<Element> KeyGen(CryptoContextSFDK<Element> cc) ;

  LPKeyCipher<Element> GenDecKeyFor(Ciphertext<Element> &cipherText, LPKeyCipherGenKey<Element> keyGen, LPXPublicKey<Element> publicKey);

  DecryptResult DecryptSfdk(Ciphertext<Element> &ciphertext, LPKeyCipher<Element> decKey, LPXPublicKey<Element> publicKey, Plaintext *plaintext);
 
  Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> ciphertext, std::vector<int64_t> &testset, CryptoContext<Element> cryptoContext, LPPrivateKey<Element> secretKey);

  Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> ciphertext, uint start, uint size, CryptoContext<Element> cryptoContext, LPPrivateKey<Element> secretKey);

  void PreparePSM(LPPrivateKey<Element> secretKey, uint maxsize, CryptoContext<Element> cryptoContext);

  Ciphertext<Element> GetZeroSpongeEncryption(
		const LPPrivateKey<Element> privateKey, 
		const LPPublicKey<Element> publicKey,
		Ciphertext<Element> ciphertext,
		usint &scale,
		bool isNotZero=false);

  Ciphertext<Element> ScaleByBits(ConstCiphertext<Element> ciphertext, usint bits);

  Element GetDecryptionError(const LPPrivateKey<Element> privateKey, Ciphertext<Element> &ciphertext, Plaintext plaintext);



 protected:
  DecryptResult ScaleAndRound(Element &b,  NativePoly *plaintext, shared_ptr<LPCryptoParametersBFVrns<Element>>  cryptoParamsBFVrns );
 private:
  std::vector<char> seed;
};

template <class Element>
class LPPublicKeyEncryptionSchemeBFVrnssfdk
    : public LPPublicKeyEncryptionSchemeSFDK<Element> {
  //using IntType = typename Element::Integer;
  //using ParmType = typename Element::Params;
  //using DggType = typename Element::DggType;
  //using DugType = typename Element::DugType;
  //using TugType = typename Element::TugType;

 public:
  LPPublicKeyEncryptionSchemeBFVrnssfdk();

  bool operator==(
      const LPPublicKeyEncryptionScheme<Element>& sch) const override {
    return dynamic_cast<const LPPublicKeyEncryptionSchemeBFVrns<Element>*>(
               &sch) != nullptr;
  }

  void Enable(PKESchemeFeature feature) override;

  virtual void Enable(usint mask) override;

  virtual usint GetEnabled() const override;

  LPKeyTupple<Element> KeyGenSfdk(CryptoContextSFDK<Element> cc) override  {
    if (m_algorithmSFDK) {
      auto kp = m_algorithmSFDK->KeyGen(cc);
      kp.publicKey->SetKeyTag(kp.secretKey->GetKeyTag());
      return kp;
    }
    PALISADE_THROW(config_error, "SFDK KeyGen operation has not been enabled");
  }

  LPKeyCipher<Element> GenDecKeyFor(Ciphertext<Element> &cipherText, LPKeyCipherGenKey<Element> keyGen, LPXPublicKey<Element> publicKey) override {
    if (m_algorithmSFDK) {
      auto kc = m_algorithmSFDK->GenDecKeyFor(cipherText, keyGen, publicKey);
      kc->SetKeyTag(keyGen->GetKeyTag());
      return kc;
    }
    PALISADE_THROW(config_error, "SFDK GenDecKeyFor operation has not been enabled");
  }

  DecryptResult DecryptSFDK(Ciphertext<Element> &ciphertext, LPKeyCipher<Element> &decKey, LPXPublicKey<Element> publicKey, Plaintext *plaintext) override {
    if (m_algorithmSFDK) {
      return m_algorithmSFDK->DecryptSfdk(ciphertext, decKey, publicKey, plaintext);
    }
    PALISADE_THROW(config_error, "SFDK Decrypt operation has not been enabled");
  }

  Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> &ciphertext, std::vector<int64_t> &testset, CryptoContext<Element> cryptoContext, LPPrivateKey<Element> secretKey) override  {
    if (m_algorithmSFDK) {
      return m_algorithmSFDK->PrivateSetMembership(ciphertext, testset, cryptoContext, secretKey);
    }
    PALISADE_THROW(config_error, "SFDK PSM operation has not been enabled");
  }

  Ciphertext<Element> PrivateSetMembership(Ciphertext<Element> &ciphertext, uint start, uint size, CryptoContext<Element> cryptoContext, LPPrivateKey<Element> secretKey) override  {
    if (m_algorithmSFDK) {
      return m_algorithmSFDK->PrivateSetMembership(ciphertext, start, size, cryptoContext, secretKey);
    }
    PALISADE_THROW(config_error, "SFDK PSM operation has not been enabled");
  }
  

  void PreparePSM(LPPrivateKey<Element> secretKey, uint maxsize, CryptoContext<Element> cryptoContext)  override {
    if (m_algorithmSFDK) {
      m_algorithmSFDK->PreparePSM(secretKey, maxsize, cryptoContext);
      return;
    }
    PALISADE_THROW(config_error, "SFDK Decrypt operation has not been enabled");
  }

  Ciphertext<Element> GetZeroSpongeEncryption(
		const LPPrivateKey<Element> privateKey, 
		const LPPublicKey<Element> publicKey,
		Ciphertext<Element> ciphertext,
		usint &scale,
		bool isNotZero=false) override {
    if (m_algorithmSFDK) {
      return m_algorithmSFDK->GetZeroSpongeEncryption(privateKey, publicKey, ciphertext, scale, isNotZero);
    }
    PALISADE_THROW(config_error, "SFDK GetZeroSponge operation has not been enabled");
  }

  Ciphertext<Element> ScaleByBits(ConstCiphertext<Element> ciphertext, usint bits) override {
    if (m_algorithmSFDK) {
      return m_algorithmSFDK->ScaleByBits(ciphertext, bits);
    }
    PALISADE_THROW(config_error, "SFDK ScaleByBits operation has not been enabled");
  }

  Element GetDecryptionError(const LPPrivateKey<Element> privateKey, Ciphertext<Element> &ciphertext, Plaintext plaintext = NULL) override {
    if (m_algorithmSFDK) {
      return m_algorithmSFDK->GetDecryptionError(privateKey, ciphertext, plaintext);
    }
    PALISADE_THROW(config_error, "SFDK Decrypt Error operation has not been enabled");
  }

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    ar(::cereal::base_class<LPPublicKeyEncryptionScheme<Element>>(this));
  }

  std::string SerializedObjectName() const override { return "BFVrnsSFDKScheme"; }

  protected:
  std::shared_ptr<LPAlgorithmSFDKBFVrns<Element>> m_algorithmSFDK;
};



}

#endif