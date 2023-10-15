#ifndef PRF_H
#define PRF_H

#include <cmath>

namespace lbcrypto {


template <class Element>
class PRF {
 public:
  /**
   * Default constructor
   */
  PRF() {}

  PRF(shared_ptr<typename Element::Params> elementParams, usint q, usint p) {
    m_p = p;
    m_q = q;
    m_l = floor(log2((double)q));


    auto zero_alloc = Element::Allocator(elementParams, Format::EVALUATION);
    auto random_alloc = MakeBinaryAllocator(elementParams, Format::EVALUATION);
    for(int i=0; i<2; i++) {
        Matrix<Element> x(zero_alloc,m_l,m_l,random_alloc);
        m_a.push_back(x);
    }
    m_a.push_back(m_a[0]-m_a[1]);

  }

  Matrix<Element> GenElement(Element seed, usint number) {
    std::vector<usint> digits = *(GetBits(number,2, m_l));
    return RoundP(seed*(Left(digits)*Right(digits)));

  }

  /**
   *Destructor
   */
  ~PRF() {}

  private:
    usint m_l;
    usint m_p;
    std::vector<Matrix<Element>> m_a;
    usint m_q;


  inline static function<Element()> MakeBinaryAllocator(
      shared_ptr<typename Element::Params> params, Format format) {
    return [=]() {
      typename Element::BugType bug;
      return Element(bug, params, format);
    };
  }

  Matrix<Element> RoundP(Matrix<Element> rnd) {
    typename Matrix<Element>::data_t data = rnd.GetData();
    size_t cols = rnd.GetCols();
    size_t rows = rnd.GetRows();
    for (size_t j = 0; j < cols; ++j) {
      for (size_t i = 0; i < rows; ++i) {
        data[i][j]=  data[i][j].MultiplyAndRound(m_p,m_q);
      }
    }
    return rnd;
  }

  Matrix<Element> Left(std::vector<usint> v) {
    if(v.size()>1) {
      size_t middle = v.size() / 2;
      std::vector<usint> part = std::vector<usint>(v.begin(),v.begin()+middle);
      return Left(part)*Right(part);
    } else {
      return m_a[v[0]];
    }
  }

  Matrix<Element> Right(std::vector<usint> v) {
    if(v.size()>1) {
      size_t middle = v.size() / 2;
      std::vector<usint> part = std::vector<usint>(v.begin()+middle,v.end());
      return Left(part)*Right(part);
    } else {
      return m_a[v[0]];
    }    
  }

  std::shared_ptr<std::vector<usint>> GetBits(const usint &u, uint64_t base,
                                                uint32_t k) {
    auto u_vec = std::make_shared<std::vector<usint>>(k);

    size_t baseDigits = (uint32_t)(std::round(log2(base)));

    // if (!(base & (base - 1)))
    usint uu = u;
    usint uTemp;
    for (size_t i = 0; i < k; i++) {  
      uTemp = uu >> baseDigits;
      (*u_vec)[i] = (uu - (uTemp << baseDigits));
      uu = uTemp;
    }
    return u_vec;
  }
    
};
}
#endif //PRF_H