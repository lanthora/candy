// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILITY_URI_H
#define CANDY_UTILITY_URI_H

#include <string>
#include <uriparser/Uri.h>

namespace Candy {

class Uri {
public:
    Uri(const char *uri);
    Uri(const std::string &uri);
    ~Uri();
    bool isValid() const;

    std::string scheme() const;
    std::string host() const;
    std::string port() const;
    std::string path() const;
    std::string query() const;
    std::string fragment() const;

private:
    UriUriA uri;
    bool valid;

    std::string fromRange(const UriTextRangeA &rng) const;
    std::string fromList(UriPathSegmentA *xs, const std::string &delim) const;
};

}; // namespace Candy

#endif
