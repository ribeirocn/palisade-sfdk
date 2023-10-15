
#ifndef SIGPVS_LWESIGN_H
#define SIGPVS_LWESIGN_H

#include "utils/inttypes.h"
#include "lattice/dgsampling.h"

namespace lbcrypto {
/**
 * @brief  Class holding parameters required for calculations in signature
 * schemes
 */
template <class Element>
class PVSignatureParameters {
 public:
  /**
   *Method for setting the ILParams held in this class
   *
   *@param params Parameters to be held, used in Element construction
   */
  void SetElemParams(std::shared_ptr<typename Element::Params> params,
                     EncodingParams encodingParams,
                     usint base = 2, bool VerifyNormFlag = false) {
    m_params = params;
    m_encodingParams = encodingParams;
    m_base = base;
    const typename Element::Integer& q = params->GetModulus();
    size_t n = params->GetRingDimension();
    usint nBits = floor(log2(q.ConvertToDouble() - 1.0) + 1.0);
    m_k = ceil(nBits / log2(base));
    double c = (base + 1) * SIGMA;
    double s = SPECTRAL_BOUND(n, m_k, base);
    if (sqrt(s * s - c * c) <= KARNEY_THRESHOLD)
      m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
    else
      m_dggLargeSigma = m_dgg;
    
    VerifyNorm = VerifyNormFlag;
  }

  /**
   *Method for accessing the ILParams held in this class
   *
   *@return Parameters held
   */
  std::shared_ptr<typename Element::Params> GetILParams() const { return m_params; }

/**
   * GetEncodingParams
   * @return Encoding params used with this plaintext
   */
  const EncodingParams GetEncodingParams() const { return m_encodingParams; }

  /**
   *Method for accessing the DiscreteGaussianGenerator object held in this class
   *
   *@return DiscreteGaussianGenerator object held
   */
  typename Element::DggType& GetDiscreteGaussianGenerator() { return m_dgg; }

  /**
   *Method for accessing the base for Gadget matrix
   *
   *@return the value of base held by the object
   */
  usint& GetBase() { return m_base; }

/**
   *Method for accessing the base for Gadget matrix
   *
   *@return the value of base held by the object
   */
  bool& GetVerifyNormFlag() { return VerifyNorm; }
  /**
   *Method for accessing the dimension for Gadget matrix
   *
   *@return the value of the dimension held by the object
   */
  usint& GetK() { return m_k; }

  /**
   *Method for accessing the DiscreteGaussianGenerator object held in this class
   *
   *@return DiscreteGaussianGenerator object held
   */
  typename Element::DggType& GetDiscreteGaussianGeneratorLargeSigma() {
    return m_dggLargeSigma;
  }

 PVSignatureParameters(std::shared_ptr<typename Element::Params> params) {}
  /**
   *Constructor
   *@param params Parameters used in Element construction
   *@param dgg DiscreteGaussianGenerator used in sampling
   */
  PVSignatureParameters(std::shared_ptr<typename Element::Params> params,
                        EncodingParams encodingParams,  
                         typename Element::DggType& dgg, usint base = 2, bool VerifyNormFlag = false)
      : m_dgg(dgg), m_base(base) {
    m_params = params;
    m_encodingParams = encodingParams;
    const typename Element::Integer& q = params->GetModulus();
    size_t n = params->GetRingDimension();
    usint nBits = floor(log2(q.ConvertToDouble() - 1.0) + 1.0);
    m_k = ceil(nBits / log2(base));
    double c = (base + 1) * SIGMA;
    double s = SPECTRAL_BOUND(n, m_k, base);
    if (sqrt(s * s - c * c) <= KARNEY_THRESHOLD)
      m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
    else
      m_dggLargeSigma = m_dgg;

    VerifyNorm = VerifyNormFlag;
  }

 private:
  // Parameters related to elements
  std::shared_ptr<typename Element::Params> m_params;

  EncodingParams m_encodingParams;
  // Discrete Gaussian Generator for random number generation
  typename Element::DggType m_dgg;
  // Discrete Gaussian Generator with high distribution parameter for random
  // number generation
  typename Element::DggType m_dggLargeSigma;
  // Trapdoor base
  usint m_base;
  // Trapdoor length
  usint m_k;

  //flag for verifying norm of signature
  bool VerifyNorm;

  /*
   *@brief Overloaded dummy method
   */
  void forceImplement() {}
};


}  // namespace lbcrypto
#endif
