

#ifndef PVS_SIGNATURECONTEXTX_H
#define PVS_SIGNATURECONTEXTX_H

#include <memory>

#include "PVSParams.h"
#include "prf.h"
#include "lattice/trapdoor.h"
#include "encoding/plaintextfactory.h"
#include <assert.h>


namespace lbcrypto {


template <class Element>
class PVSSignKey {
 public:
  /**
   * Default constructor
   */
  PVSSignKey() {}

  /**Constructor
   *
   * @param x trapdoor pair used for signing
   */
  explicit PVSSignKey(std::shared_ptr<RLWETrapdoorPair<Element>> x) {
    this->m_sk = (x);
  }

  /**
   *Destructor
   */
  ~PVSSignKey() {}

  /**
   *Method for accessing key in signing process
   *
   *@return Key used in signing
   */
  const RLWETrapdoorPair<Element>& GetSignKey() const { return *m_sk; }
  /**
   *Method for setting the private key used in the signing process
   *
   *@param &x a trapdoor pair used for signing
   */
  void SetSignKey(shared_ptr<RLWETrapdoorPair<Element>> x) { this->m_sk = (x); }

 private:
  // Trapdoor pair acting as signing key
  shared_ptr<RLWETrapdoorPair<Element>> m_sk;
  /*
   *@brief Overloaded dummy method
   */
  void forceImplement() {}
};

/**
 * @brief Class holding verification key for Ring LWE variant of GPV signing
 * algorithm with GM17 improvements. The value held in this class is the  public
 * key of the trapdoor
 * @tparam is the ring element
 */
template <class Element>
class PVSVerificationKey  {
 public:
  /**
   *  Default constructor
   */
  PVSVerificationKey() {}

  /**
   * Constructor
   * @param vk Verification key
   */
  explicit PVSVerificationKey(shared_ptr<Matrix<Element>> vk, usint q) {
    SetVerificationKey(vk,q);
  }

  /**
   *  Destructor
   */
  ~PVSVerificationKey() {}
  /**
   *Method for accessing key in verification process
   *
   *@return Key used in verification
   */
  const Matrix<Element>& GetVerificationKey() const { return *m_vk; }
  /**
   * Method for setting key used in verification process
   *
   * @param x Key used in verification
   */
  void SetVerificationKey(shared_ptr<Matrix<Element>> vk,usint q) { 
    this->m_vk = vk;
    if(vk && vk->GetData().size() != 0) {
      m_params = vk->GetData()[0][0].GetParams();
      auto ru = m_params->GetRootOfUnity();
      //auto ru = m_params->GetParams()[0]->GetRootOfUnity();
      std::shared_ptr<typename NativePoly::Params> ilParams =
        std::make_shared<NativePoly::Params>(
          m_params->GetCyclotomicOrder(),
          m_params->GetModulus(), 
          ru);
          //m_params->GetRootOfUnity());

      m_prf = PRF<NativePoly>(ilParams, q, 2);
      typename NativePoly::DugType dug;
      m_seed = NativePoly(dug, ilParams, Format::EVALUATION);
    }
  }

  NativePoly GetSeed() {
    return m_seed;
  }

  void SetSeed(NativePoly seed) {
    m_seed = seed;
  }

  std::pair<Element,Element> GetPubKeyInstance(usint number) {
    Matrix<NativePoly> prg = m_prf.GenElement(m_seed, number);
    //Element a1(prg.GetData()[0][0],Format::EVALUATION);
    //Element a2(prg.GetData()[1][0],Format::EVALUATION);

    Element a1(prg.GetData()[0][0],m_params);
    Element a2(prg.GetData()[1][0],m_params);
    return std::pair<Element,Element>(a1,a2);
  }

 private:
  // Public key from trapdoor acting as verification key
  shared_ptr<Matrix<Element>> m_vk;
  shared_ptr<typename Element::Params> m_params;
  NativePoly m_seed;
  PRF<NativePoly> m_prf;

  /*
   *@brief Overloaded dummy method
   */
  void forceImplement() {}
};

template <class Element>
class PVSignature {
  private:
    Matrix<Element> m_signature;
    usint m_seq;
    std::pair<Element,Element> m_pubKey;

  public:
    PVSignature() {}
    PVSignature(Matrix<Element> s, usint seq, std::pair<Element,Element> pubKey) {
      m_signature = s;
      m_seq = seq;
      m_pubKey = pubKey;
    }

    Matrix<Element> GetSignData() {
      return m_signature;
    }

    usint GetSignedSeq() {
      return m_seq;
    }

    std::pair<Element,Element> GetPubKey() {    
      return m_pubKey;
    }

    void SetPubKey(std::pair<Element,Element> pubKey) {
      m_pubKey = pubKey;
    }
};

/**
 *@brief Context class for signature schemes, including GPV
 *@tparam Element ring element
 */
template <class Element>
class PVSContext {
  public:
  /*
   *@brief Default constructor
   */
  PVSContext() {}
  /**
   *@brief Method for setting up a GPV context with specific parameters
   *@param ringsize Desired ringsize
   *@param bitwidth Desired modulus bitwidth
   *@param base Base ofIL the gadget matrix
   */
  void GeneratePVSContext(usint ringsize, usint bits, usint base, bool VerifyNorm) {
    usint sm = ringsize * 2;
    double stddev = SIGMA;
    typename Element::DggType dgg(stddev);
    typename Element::Integer srootOfUnity;

    m_smodulus = FirstPrime<typename Element::Integer>(bits, sm);
    srootOfUnity = RootOfUnity(sm, m_smodulus);
    //ILParamsImpl<typename Element::Integer> ilParams =
    //  ILParamsImpl<typename Element::Integer>(sm, m_smodulus, srootOfUnity);

    ChineseRemainderTransformFTT<typename Element::Vector>::PreCompute(
      srootOfUnity, sm, m_smodulus);
  
    DiscreteFourierTransform::PreComputeTable(sm);

   // auto silparams =
   //   std::make_shared<ILParamsImpl<typename Element::Integer>>(ilParams);

    auto silparams = std::make_shared<typename Element::Params>(sm, m_smodulus, srootOfUnity);
    auto a = PVSignatureParameters<Element>(
         silparams, 
         EncodingParams(std::make_shared<EncodingParamsImpl>(m_smodulus.ConvertToInt())), 
         dgg, base, VerifyNorm
         );
    m_params =
      std::make_shared<PVSignatureParameters<Element>>(
         silparams, 
         EncodingParams(std::make_shared<EncodingParamsImpl>(m_smodulus.ConvertToInt())), 
         dgg, base, VerifyNorm
         );

    m_seq = 0;
  }
 
  /**
   *@brief Method for key generation
   *@param sk Signing key for sign operation - Output
   *@param vk Verification key for verify operation - Output
   */
  void KeyGen(PVSSignKey<Element>* sk, PVSVerificationKey<Element>* vk) {

    shared_ptr<typename Element::Params> params = m_params->GetILParams();
    auto stddev = m_params->GetDiscreteGaussianGenerator().GetStd();
    usint base = m_params->GetBase();



    // Generate trapdoor based using parameters and
    std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> keyPair =
      RLWETrapdoorUtility<Element>::TrapdoorGen(params, stddev, base);
    // Format of vectors are changed to prevent complications in calculations

    keyPair.second.m_e.SetFormat(Format::EVALUATION);
    keyPair.second.m_r.SetFormat(Format::EVALUATION);
    keyPair.first.SetFormat(Format::EVALUATION);
    // Verification key will be set to the uniformly sampled matrix used in
    // trapdoor
    vk->SetVerificationKey(
      std::make_shared<Matrix<Element>>(keyPair.first),m_smodulus.ConvertToInt());

    // Signing key will contain public key matrix of the trapdoor and the trapdoor
    // matrices
    sk->SetSignKey(
      std::make_shared<RLWETrapdoorPair<Element>>(keyPair.second));
  }
 
  /**
   *@brief Method for signing a given plaintext
   *@param pt Plaintext to be signed
   *@param sk Sign key
   *@param vk Verification key
   *@param sign Signature corresponding to the plaintext - Output
   */
  PVSignature<Element> Sign(Plaintext data, PVSSignKey<Element>& sk, PVSVerificationKey<Element>& vk) {


    std::pair<Element,Element> pk = vk.GetPubKeyInstance(m_seq);
    //std::pair<Matrix<Element>,Matrix<Element>> sample = Sample(sk,vk,pk);
    size_t n = m_params->GetILParams()->GetRingDimension();
    size_t k = m_params->GetK();
    size_t base = m_params->GetBase();

    typename Element::DggType &dgg = m_params->GetDiscreteGaussianGenerator();
    const Matrix<Element> &A = vk.GetVerificationKey();
    const RLWETrapdoorPair<Element> &T = sk.GetSignKey();
    typename Element::DggType &dggLargeSigma = m_params->GetDiscreteGaussianGeneratorLargeSigma();


    Matrix<Element> zHat0 = RLWETrapdoorUtility<Element>::GaussSamp(n, k, A, T, pk.first, dgg, dggLargeSigma, base);
    Matrix<Element> zHat1 = RLWETrapdoorUtility<Element>::GaussSamp(n, k, A, T, pk.second, dgg, dggLargeSigma, base);

    Element mu = data->GetElement<Element>();
    mu.SetFormat(Format::EVALUATION);

    return PVSignature<Element>(mu*zHat0+zHat1,m_seq++,pk);
  }

  /**
   *@brief Method for verifying the plaintext and signature
   *@param pt Plaintext
   *@param signature Signature to be verified
   *@param vk Key used for verification
   *@return Verification result
   */
  bool Verify(PVSVerificationKey<Element>& vk, PVSignature<Element>& z, Plaintext data) {
    Element mu = data->GetElement<Element>();
    mu.SetFormat(Format::EVALUATION);

    std::pair<Element,Element> pk = vk.GetPubKeyInstance(z.GetSignedSeq());
    if(pk != z.GetPubKey()) {

        PALISADE_THROW(lbcrypto::math_error, "differen pub keys ");
    }
    return (vk.GetVerificationKey()*z.GetSignData())(0,0) == mu*pk.first+pk.second;
  }

  usint GetSeq() { return m_seq; }


    /**
   * Getter for element params
   * @return
   */
    const typename std::shared_ptr<typename Element::Params> GetElementParams() const {
      return m_params->GetILParams();
    }

    /**
   * Getter for encoding params
   * @return
   */
    const EncodingParams GetEncodingParams() const {
        return m_params->GetEncodingParams();
    }

  // PLAINTEXT FACTORY METHODS
  // TODO to be deprecated in 2.0
  /**
   * MakeStringPlaintext constructs a StringEncoding in this context
   * @param str
   * @return plaintext
   */
  Plaintext MakeStringPlaintext(const string& str) const {
    auto p = PlaintextFactory::MakePlaintext(String, this->GetElementParams(),
                                             this->GetEncodingParams(), str);
    return p;
  }

  /**
   * MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context
   * @param value
   * @return plaintext
   */
  Plaintext MakeCoefPackedPlaintext(const vector<int64_t>& value) const {
    auto p = PlaintextFactory::MakePlaintext(
        CoefPacked, this->GetElementParams(), this->GetEncodingParams(), value);
    return p;
  }

  /**
   * MakePackedPlaintext constructs a PackedEncoding in this context
   * @param value
   * @return plaintext
   */
  Plaintext MakePackedPlaintext(const vector<int64_t>& value) const {
    auto p = PlaintextFactory::MakePlaintext(Packed, this->GetElementParams(),
                                             this->GetEncodingParams(), value);
    return p;
  }

  /**
   * MakePlaintext static that takes a cc and calls the Plaintext Factory
   * @param encoding
   * @param cc
   * @param value
   * @return
   */
  template <typename Value1>
  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 PVSContext<Element> cc,
                                 const Value1& value) {
    return PlaintextFactory::MakePlaintext(encoding, cc->GetElementParams(),
                                           cc->GetEncodingParams(), value);
  }

  template <typename Value1, typename Value2>
  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 PVSContext<Element> cc, const Value1& value,
                                 const Value2& value2) {
    return PlaintextFactory::MakePlaintext(encoding, cc->GetElementParams(),
                                           cc->GetEncodingParams(), value,
                                           value2);
  }

private:
  // Parameters related to the scheme
  shared_ptr<PVSignatureParameters<Element>> m_params;
  usint m_seq;
  typename Element::Integer m_smodulus;
};



}  // namespace lbcrypto



#endif

