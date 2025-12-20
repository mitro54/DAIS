#include "core/engine.hpp"

int main() {
    dash::core::Engine engine;
    engine.load_extensions("plugins");
    engine.run();
    return 0;
}