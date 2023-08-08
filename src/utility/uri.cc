// SPDX-License-Identifier: MIT
#include "utility/uri.h"

namespace Candy {

Uri::Uri(const std::string &uri) {
    UriParserStateA state;
    state.uri = &this->uri;
    this->valid = (uriParseUriA(&state, uri.c_str()) == URI_SUCCESS);
}

Uri::~Uri() {
    uriFreeUriMembersA(&this->uri);
}

bool Uri::isValid() const {
    return this->valid;
}

std::string Uri::scheme() const {
    return fromRange(this->uri.scheme);
}

std::string Uri::host() const {
    return fromRange(this->uri.hostText);
}

std::string Uri::port() const {
    return fromRange(this->uri.portText);
}

std::string Uri::path() const {
    return fromList(this->uri.pathHead, "/");
}

std::string Uri::query() const {
    return fromRange(this->uri.query);
}

std::string Uri::fragment() const {
    return fromRange(this->uri.fragment);
}

std::string Uri::fromRange(const UriTextRangeA &rng) const {
    return std::string(rng.first, rng.afterLast);
}

std::string Uri::fromList(UriPathSegmentA *xs, const std::string &delim) const {
    UriPathSegmentStructA *head(xs);
    std::string accum;

    while (head) {
        accum += delim + fromRange(head->text);
        head = head->next;
    }

    return accum;
}

}; // namespace Candy
