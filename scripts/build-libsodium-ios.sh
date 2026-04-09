#!/usr/bin/env bash

set -euo pipefail

# Use the immutable point release tarball here. Stable tarballs are intentionally
# mutable, which is useful for app build hooks but not ideal for checked-in
# artifacts that we want to regenerate deterministically.
LIBSODIUM_VERSION="${LIBSODIUM_VERSION:-1.0.21}"
LIBSODIUM_SHA256="${LIBSODIUM_SHA256:-9e4285c7a419e82dedb0be63a72eea357d6943bc3e28e6735bf600dd4883feaf}"
LIBSODIUM_URL="${LIBSODIUM_URL:-https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz}"
MIN_IOS_VERSION="${MIN_IOS_VERSION:-14.0}"

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${BUILD_ROOT:-${ROOT_DIR}/build/ios-libsodium}"
DOWNLOAD_DIR="${BUILD_ROOT}/downloads"
WORK_ROOT="${BUILD_ROOT}/work"
PREBUILT_DIR="${ROOT_DIR}/ios/prebuilt"

ARCHIVE_NAME="libsodium-${LIBSODIUM_VERSION}.tar.gz"
ARCHIVE_PATH="${LIBSODIUM_ARCHIVE_PATH:-${DOWNLOAD_DIR}/${ARCHIVE_NAME}}"

DEVICE_OUTPUT="${PREBUILT_DIR}/libsodium-device.a"
SIMULATOR_OUTPUT="${PREBUILT_DIR}/libsodium-simulator.a"
BUILD_INFO_OUTPUT="${PREBUILT_DIR}/libsodium-build-info.json"

JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

log() {
  printf '==> %s\n' "$*"
}

ensure_commands() {
  local command
  for command in curl shasum tar make xcrun lipo; do
    if ! command -v "${command}" >/dev/null 2>&1; then
      printf 'Missing required command: %s\n' "${command}" >&2
      exit 1
    fi
  done
}

download_archive() {
  mkdir -p "${DOWNLOAD_DIR}"

  if [[ ! -f "${ARCHIVE_PATH}" ]]; then
    log "Downloading ${LIBSODIUM_URL}"
    curl --fail --location --output "${ARCHIVE_PATH}" "${LIBSODIUM_URL}"
  else
    log "Using existing archive at ${ARCHIVE_PATH}"
  fi

  local actual_sha
  actual_sha="$(shasum -a 256 "${ARCHIVE_PATH}" | awk '{print $1}')"
  if [[ "${actual_sha}" != "${LIBSODIUM_SHA256}" ]]; then
    printf 'Checksum mismatch for %s\nExpected: %s\nActual:   %s\n' \
      "${ARCHIVE_PATH}" "${LIBSODIUM_SHA256}" "${actual_sha}" >&2
    exit 1
  fi
}

extract_source() {
  local destination="$1"

  rm -rf "${destination}"
  mkdir -p "${destination}"
  tar -xzf "${ARCHIVE_PATH}" -C "${destination}"
  printf '%s/libsodium-%s\n' "${destination}" "${LIBSODIUM_VERSION}"
}

build_target() {
  local name="$1"
  local sdk="$2"
  local arch="$3"
  local host="$4"
  local version_flag="$5"
  local prefix="$6"
  local source_root="$7"

  local sdk_path clang ar ranlib strip source_dir build_triplet config_guess
  sdk_path="$(xcrun --sdk "${sdk}" --show-sdk-path)"
  clang="$(xcrun --sdk "${sdk}" --find clang)"
  ar="$(xcrun --sdk "${sdk}" --find ar)"
  ranlib="$(xcrun --sdk "${sdk}" --find ranlib)"
  strip="$(xcrun --sdk "${sdk}" --find strip)"
  source_dir="$(extract_source "${source_root}")"

  if [[ -x "${source_dir}/config.guess" ]]; then
    config_guess="${source_dir}/config.guess"
  elif [[ -x "${source_dir}/build-aux/config.guess" ]]; then
    config_guess="${source_dir}/build-aux/config.guess"
  else
    printf 'Unable to locate config.guess in %s\n' "${source_dir}" >&2
    exit 1
  fi

  log "Building ${name}"
  build_triplet="$(${config_guess})"

  pushd "${source_dir}" >/dev/null
  env \
    CC="${clang}" \
    AR="${ar}" \
    RANLIB="${ranlib}" \
    STRIP="${strip}" \
    CFLAGS="-O3 -arch ${arch} -isysroot ${sdk_path} ${version_flag}" \
    LDFLAGS="-arch ${arch} -isysroot ${sdk_path} ${version_flag}" \
    ./configure \
      --build="${build_triplet}" \
      --host="${host}" \
      --disable-shared \
      --enable-static \
      --prefix="${prefix}"
  make -j"${JOBS}"
  make install
  popd >/dev/null
}

write_build_info() {
  cat > "${BUILD_INFO_OUTPUT}" <<EOF2
{
  "libsodium_version": "${LIBSODIUM_VERSION}",
  "source_url": "${LIBSODIUM_URL}",
  "source_sha256": "${LIBSODIUM_SHA256}",
  "min_ios_version": "${MIN_IOS_VERSION}",
  "device_archive": "$(basename "${DEVICE_OUTPUT}")",
  "device_archs": ["arm64"],
  "simulator_archive": "$(basename "${SIMULATOR_OUTPUT}")",
  "simulator_archs": ["arm64", "x86_64"]
}
EOF2
}

main() {
  ensure_commands
  download_archive

  mkdir -p "${WORK_ROOT}" "${PREBUILT_DIR}"

  local device_prefix="${WORK_ROOT}/device/install"
  local sim_arm64_prefix="${WORK_ROOT}/sim-arm64/install"
  local sim_x86_64_prefix="${WORK_ROOT}/sim-x86_64/install"

  build_target \
    "iPhoneOS arm64" \
    "iphoneos" \
    "arm64" \
    "aarch64-apple-darwin" \
    "-mios-version-min=${MIN_IOS_VERSION}" \
    "${device_prefix}" \
    "${WORK_ROOT}/device/src"

  build_target \
    "iPhoneSimulator arm64" \
    "iphonesimulator" \
    "arm64" \
    "aarch64-apple-darwin" \
    "-mios-simulator-version-min=${MIN_IOS_VERSION}" \
    "${sim_arm64_prefix}" \
    "${WORK_ROOT}/sim-arm64/src"

  build_target \
    "iPhoneSimulator x86_64" \
    "iphonesimulator" \
    "x86_64" \
    "x86_64-apple-darwin" \
    "-mios-simulator-version-min=${MIN_IOS_VERSION}" \
    "${sim_x86_64_prefix}" \
    "${WORK_ROOT}/sim-x86_64/src"

  cp "${device_prefix}/lib/libsodium.a" "${DEVICE_OUTPUT}"
  lipo -create \
    "${sim_arm64_prefix}/lib/libsodium.a" \
    "${sim_x86_64_prefix}/lib/libsodium.a" \
    -output "${SIMULATOR_OUTPUT}"

  write_build_info

  log "Created $(basename "${DEVICE_OUTPUT}"): $(lipo -info "${DEVICE_OUTPUT}")"
  log "Created $(basename "${SIMULATOR_OUTPUT}"): $(lipo -info "${SIMULATOR_OUTPUT}")"
  log "Wrote $(basename "${BUILD_INFO_OUTPUT}")"
}

main "$@"
