/*
 * Callback for illegal arguments passed to libsecp256k1.
 *
 * The default callback of libsecp256k1 prints a message and calls abort(),
 * which terminates the Haskell program. With this callback installed, the
 * library function that received the illegal argument returns 0 instead, and
 * the Haskell binding reports the failure as Nothing or as an exception.
 */
void secp256k1_haskell_illegal_callback(const char *message, void *data) {
  (void)message;
  (void)data;
}
