packages:=gmp

libomp_packages = libomp

boost_packages = boost

libevent_packages = libevent

sqlite_packages=sqlite

zmq_packages=zeromq

multiprocess_packages = libmultiprocess capnp
multiprocess_native_packages = native_libmultiprocess native_capnp

usdt_linux_packages=systemtap

# Darwin no longer needs a depends-managed toolchain: the guix profile
# defined by contrib/guix/manifest.scm's darwin branch ships clang +
# llvm-* + lld, and depends/hosts/darwin.mk wires them via PATH. The
# old native_llvm / native_libtapi / native_cctools chain was retired
# when navio moved to upstream's modernized darwin guix path.
darwin_native_packages =
