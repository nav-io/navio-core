## Startup options

- The legacy `-checkpoints` debug option has been removed along with the
  Bitcoin-era checkpoint data it controlled, which could never reject a navio
  block. Setting `-checkpoints` is still accepted but has no effect: the node
  starts normally and logs the warning "Option '-checkpoints' is set but
  checkpoints were removed. This option has no effect." Remove it from your
  configuration to silence the warning. The finality checkpoints that reject
  forks from the agreed chain are unaffected and, as before, cannot be turned
  off.
