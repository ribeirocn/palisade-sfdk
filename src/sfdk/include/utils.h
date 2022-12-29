#ifndef SRC_SFDK_SFDKUTILS_H_
#define SRC_SFDK_SFDKUTILS_H_

#include "palisade.h"

namespace lbcrypto {
template <typename Element>
class SdfkUtils  {
 public:

 static Element dotProd(const Matrix<Element> &_a, const Matrix<Element> &_b) {
    std::vector<std::vector<Element>> a = _a.GetData();
    std::vector<std::vector<Element>> b = _b.GetData();
    if(a.size() == 0 || b.size() == 0) {
        PALISADE_THROW(config_error,"First or Second Elements is empty");
    }

    Element result = a[0][0]*b[0][0];
    if(a.size() == 1 && b.size() == 1) {
        if(a[0].size() != b[0].size()) {
            PALISADE_THROW(config_error,"Vectors are not of the same size");
        }
        for(usint i=1; i<a[0].size(); i++) {
            result += a[0][i]*b[0][i];
        }
    } else if(a[0].size() == 1 && b[0].size() == 1) {
        if(a.size() != b.size()) {
            PALISADE_THROW(config_error,"Vectors are not of the same size");
        }
        for(usint i=1; i<a.size(); i++) {
            result += a[i][0]*b[i][0];
        }
    } else if(a.size() == 1 && b[0].size() == 1) {
        if(a[0].size() != b.size()) {
            PALISADE_THROW(config_error,"Vectors are not of the same size");
        }
        for(usint i=1; i<a[0].size(); i++) {
            result += a[0][i]*b[i][0];
        }
    } else if(a[0].size() == 1 && b.size() == 1) {
        if(a[0].size() != b.size()) {
            PALISADE_THROW(config_error,"Vectors are not of the same size");
        }
        for(usint i=1; i<a[0].size(); i++) {
            result += a[0][i]*b[i][0];
        }
    } else {
        PALISADE_THROW(config_error,"First or Second Element is not a vector");
    }

    return result;
 }
};
}
#endif // SRC_SFDK_SFDKUTILS_H_