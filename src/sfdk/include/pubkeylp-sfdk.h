#ifndef SRC_SFDK_PUBLICKEYLP_H_
#define SRC_SFDK_PUBLICKEYLP_H_

#include "palisade.h"
#include "lattice/trapdoor.h"
#include "pke/scheme/rlwe.h"
#include "pke/pubkeylp.h"

namespace lbcrypto {

template <typename Element>
class LPLargePublicKeyImpl;

template <typename Element>
class LPKeyCipherImpl;

template <typename Element>
class LPKeyCipherGenKeyImpl;

template <typename Element>
class LPKeyTuppleImpl;

template <typename Element>
using LPXPublicKey = shared_ptr<LPLargePublicKeyImpl<Element>>;

template <typename Element>
using LPKeyCipher = shared_ptr<LPKeyCipherImpl<Element>>;

template <typename Element>
using LPKeyCipherGenKey = shared_ptr<LPKeyCipherGenKeyImpl<Element>>;

template <typename Element>
using LPKeyTupple = LPKeyTuppleImpl<Element>;

template <typename Element>
class LPLargePublicKeyImpl : public LPPublicKeyImpl<Element> {
 public:
  /**
   * Basic constructor
   *
   * @param cc - CryptoContext
   * @param id - key identifier
   */
  explicit LPLargePublicKeyImpl(CryptoContext<Element> cc = 0, const string &id = "")
      : LPPublicKeyImpl<Element>(cc, id) {}

  /**
   * Copy constructor
   *
   *@param &rhs LPLargePublicKeyImpl to copy from
   */
  explicit LPLargePublicKeyImpl(const LPLargePublicKeyImpl<Element> &rhs)
      : LPPublicKeyImpl<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
    m_xh = rhs.m_xh;
  }

  /**
   * Move constructor
   *
   *@param &rhs LPLargePublicKeyImpl to move from
   */
  explicit LPLargePublicKeyImpl(LPLargePublicKeyImpl<Element> &&rhs)
      : LPPublicKeyImpl<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
    m_xh = std::move(rhs.m_xh);
  }

  operator bool() const {
    return static_cast<bool>(this->context) && m_xh.size() != 0;
  }

  /**
   * Assignment Operator.
   *
   * @param &rhs LPLargePublicKeyImpl to copy from
   */
  const LPLargePublicKeyImpl<Element> &operator=(
      const LPLargePublicKeyImpl<Element> &rhs) {
    CryptoObject<Element>::operator=(rhs);
    this->m_xh = rhs.m_xh;
    return *this;
  }

  /**
   * Move Assignment Operator.
   *
   * @param &rhs LPLargePublicKeyImpl to copy from
   */
  const LPLargePublicKeyImpl<Element> &operator=(LPLargePublicKeyImpl<Element> &&rhs) {
    CryptoObject<Element>::operator=(rhs);
    m_xh = std::move(rhs.m_xh);
    return *this;
  }

  // @Get Properties

  /**
   * Gets the computed public key
   * @return the public key element.
   */
  const std::vector<Matrix<Element>> &GetLargePublicElements() const { return this->m_xh; }

  // @Set Properties

  /**
   * Sets the public key vector of Element.
   * @param &element is the public key Element vector to be copied.
   */
  void SetLargePublicElements(const std::vector<Matrix<Element>> &element) { m_xh = element; }

  /**
   * Sets the public key vector of Element.
   * @param &&element is the public key Element vector to be moved.
   */
  void SetLargePublicElements(std::vector<Matrix<Element>> &&element) {
    m_xh = std::move(element);
  }

  /**
   * Sets the public key Element at index idx.
   * @param &element is the public key Element to be copied.
   */
  void SetLargePublicElementAtIndex(usint idx, const Matrix<Element> &element) {
    m_xh.insert(m_xh.begin() + idx, element);
  }

  /**
   * Sets the public key Element at index idx.
   * @param &&element is the public key Element to be moved.
   */
  void SetLargePublicElementAtIndex(usint idx, Matrix<Element> &&element) {
    m_xh.insert(m_xh.begin() + idx, std::move(element));
  }

  bool operator==(const LPLargePublicKeyImpl &other) const {
    if (!CryptoObject<Element>::operator==(other)) {
      return false;
    }

    if (m_xh.size() != other.m_xh.size()) {
      return false;
    }

    for (size_t i = 0; i < m_xh.size(); i++) {
      if (m_xh[i] != other.m_xh[i]) {
        return false;
      }
    }

    return true;
  }

  bool operator!=(const LPLargePublicKeyImpl &other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::base_class<LPKey<Element>>(this));
    ar(::cereal::make_nvp("h", m_xh));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::base_class<LPKey<Element>>(this));
    ar(::cereal::make_nvp("h", m_xh));
  }

  std::string SerializedObjectName() const { return "PublicSFDKKey"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  std::vector<Matrix<Element>> m_xh;
};

template <class Element>
class LPKeyCipherGenKeyImpl : public LPKey<Element> {
  public:
    LPKeyCipherGenKeyImpl(shared_ptr<RLWETrapdoorPair<Element>> trapdoor, LPXPublicKey<Element> publicKey) : 
      LPKey<Element>(publicKey->GetCryptoContext(), publicKey->GetKeyTag()), m_key(trapdoor) {

    }
    LPKeyCipherGenKeyImpl(CryptoContext<Element> cc = 0, const string &id = "")
      : LPKey<Element>(cc, id) {}

    LPKeyCipherGenKeyImpl(const LPKeyCipherGenKeyImpl<Element> &rhs)
      : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
      this->m_key = rhs.m_key;
    }

    LPKeyCipherGenKeyImpl(LPKeyCipherGenKeyImpl<Element> &&rhs)
      : LPKey<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
        this->m_key = std::move(rhs.m_key);
    }

    operator bool() const { return static_cast<bool>(this->context); }

    const LPKeyCipherGenKeyImpl<Element> &operator=(const LPKeyCipherGenKeyImpl<Element> &rhs) {
        CryptoObject<Element>::operator=(rhs);
        this->m_key = rhs.m_key;
        return *this;
    }

    const LPKeyCipherGenKeyImpl<Element> &operator=(LPKeyCipherGenKeyImpl<Element> &&rhs) {
        CryptoObject<Element>::operator=(rhs);
        this->m_key = std::move(rhs.m_key);
        return *this;
    }

    const shared_ptr<RLWETrapdoorPair<Element>> GetPrivateElement() const { return m_key; }

    void SetPrivateElement(const shared_ptr<RLWETrapdoorPair<Element>> x) { m_key = x; }

    bool operator==(const LPKeyCipherGenKeyImpl &other) const {
        return CryptoObject<Element>::operator==(other) && m_key == other.m_key;
    }

    bool operator!=(const LPKeyCipherGenKeyImpl &other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive &ar, std::uint32_t const version) const {
        ar(::cereal::base_class<LPKey<Element>>(this));
        ar(::cereal::make_nvp("s", m_key));
    }

    template <class Archive>
    void load(Archive &ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::base_class<LPKey<Element>>(this));
        ar(::cereal::make_nvp("s", m_key));
    }

    std::string SerializedObjectName() const { return "KeyCipherGenKey"; }
    static uint32_t SerializedVersion() { return 1; }


  protected:
    shared_ptr<RLWETrapdoorPair<Element>> m_key;
};


template <class Element>
class LPKeyCipherImpl : public CryptoObject<Element> {
  public:
    explicit LPKeyCipherImpl(shared_ptr<Matrix<Element>> key, LPXPublicKey<Element> publicKey) : 
      CryptoObject<Element>(publicKey->GetCryptoContext(), publicKey->GetKeyTag()), m_key(key) {
      }
  shared_ptr<Matrix<Element>> getPrivateElement() {
    return m_key;
  }
  protected:
    shared_ptr<Matrix<Element>> m_key;
};

template <class Element>
class LPKeyTuppleImpl {
 public:
  LPXPublicKey<Element> publicKey;
  LPPrivateKey<Element> secretKey;
  LPKeyCipherGenKey<Element> cipherKeyGen;

  LPKeyTuppleImpl() {};

  LPKeyTuppleImpl(LPXPublicKey<Element> a, LPPrivateKey<Element> b, LPKeyCipherGenKey<Element> c)
      : publicKey(a), secretKey(b), cipherKeyGen(c) {}

  bool good() { return publicKey && secretKey && cipherKeyGen; }
};



}
#endif /* SRC_SFDK_PUBLICKEYLP_H_ */