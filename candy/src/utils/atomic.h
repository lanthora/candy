// SPDX-License-Identifier: MIT
#ifndef CANDY_UTILS_ATOMIC_H
#define CANDY_UTILS_ATOMIC_H

#include <condition_variable>

namespace candy {
namespace Utils {

template <typename T> class Atomic {
public:
    explicit Atomic(T initial = T()) : value(initial) {}

    T load() const {
        std::lock_guard<std::mutex> lock(mutex);
        return value;
    }

    void store(T new_value) {
        std::lock_guard<std::mutex> lock(mutex);
        value = new_value;
        cv.notify_all();
    }

    void wait(const T &expected) {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this, &expected] { return value != expected; });
    }

    template <typename Predicate> void wait_until(Predicate pred) {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, pred);
    }

    void notify_one() {
        std::lock_guard<std::mutex> lock(mutex);
        cv.notify_one();
    }

    void notify_all() {
        std::lock_guard<std::mutex> lock(mutex);
        cv.notify_all();
    }

private:
    T value;
    mutable std::mutex mutex;
    std::condition_variable cv;
};

} // namespace Utils
} // namespace candy

#endif
