/*
 * Illegal-argument callback installed on every context this package creates.
 *
 * The default callback of libsecp256k1 prints the message to stderr and calls
 * abort(). That kills the whole Haskell process and cannot be caught. With
 * this callback installed, the C function that received the illegal argument
 * returns 0 instead, and the Haskell side turns that into Nothing, False or
 * an ErrorCall exception.
 *
 * The error callback, which reports internal consistency failures of the
 * library itself, keeps its default. Those indicate a broken build and
 * should still abort.
 */
void secp256k1_haskell_illegal_callback(const char *message, void *data) {
  (void)message;
  (void)data;
}
