# ClusterFuzzLite builder. The base image ships the current nightly Rust and cargo-fuzz.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1
COPY . $SRC/spillgate
WORKDIR $SRC/spillgate
COPY .clusterfuzzlite/build.sh $SRC/
