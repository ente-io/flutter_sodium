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

XCODE_VERSION=""
XCODE_BUILD_VERSION=""
IPHONEOS_SDK_VERSION=""
IPHONESIMULATOR_SDK_VERSION=""

log() {
  printf '==> %s\n' "$*"
}

ensure_commands() {
  local command
  for command in curl grep shasum tar make xcodebuild xcrun lipo sed; do
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

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

detect_xcode_metadata() {
  XCODE_VERSION="$(xcodebuild -version | awk 'NR == 1 { print $2 }')"
  XCODE_BUILD_VERSION="$(xcodebuild -version | awk 'NR == 2 { print $3 }')"
  IPHONEOS_SDK_VERSION="$(xcrun --sdk iphoneos --show-sdk-version)"
  IPHONESIMULATOR_SDK_VERSION="$(xcrun --sdk iphonesimulator --show-sdk-version)"
}

build_archives_from_upstream() {
  local source_root="$1"

  local source_dir helper_script split_marker split_marker_count
  source_dir="$(extract_source "${source_root}")"
  helper_script="${WORK_ROOT}/apple-xcframework-functions.sh"
  split_marker='mkdir -p "${PREFIX}/tmp"'

  if [[ ! -f "${source_dir}/dist-build/apple-xcframework.sh" ]]; then
    printf 'Unable to locate upstream build script: %s\n' "${source_dir}/dist-build/apple-xcframework.sh" >&2
    exit 1
  fi

  split_marker_count="$(grep -Fxc -- "${split_marker}" "${source_dir}/dist-build/apple-xcframework.sh" || true)"
  if [[ "${split_marker_count}" != "1" ]]; then
    printf 'Expected exactly one upstream split marker in %s, found %s\n' \
      "${source_dir}/dist-build/apple-xcframework.sh" "${split_marker_count}" >&2
    exit 1
  fi

  sed '/^mkdir -p "${PREFIX}\/tmp"$/,$d; s#\./configure #./configure --disable-shared --enable-static #g' \
    "${source_dir}/dist-build/apple-xcframework.sh" > "${helper_script}"
  if [[ ! -s "${helper_script}" ]]; then
    printf 'Unable to extract helper definitions from %s\n' "${source_dir}/dist-build/apple-xcframework.sh" >&2
    exit 1
  fi

  log "Building iOS archives via dist-build/apple-xcframework.sh"
  pushd "${source_dir}" >/dev/null
  export IOS_VERSION_MIN="${MIN_IOS_VERSION}"
  export IOS_SIMULATOR_VERSION_MIN="${MIN_IOS_VERSION}"
  export LIBSODIUM_MINIMAL_BUILD=""
  export LIBSODIUM_SKIP_SIMULATORS=""
  source "${helper_script}"
  if ! declare -F build_ios >/dev/null 2>&1; then
    printf 'build_ios was not defined after sourcing %s\n' "${helper_script}" >&2
    exit 1
  fi
  if ! declare -F build_ios_simulator >/dev/null 2>&1; then
    printf 'build_ios_simulator was not defined after sourcing %s\n' "${helper_script}" >&2
    exit 1
  fi

  mkdir -p "${PREFIX}/tmp"
  if ! ( build_ios ) >"${LOG_FILE}" 2>&1; then
    printf 'Upstream iOS build failed. See %s\n' "${LOG_FILE}" >&2
    exit 1
  fi
  if ! ( build_ios_simulator ) >>"${LOG_FILE}" 2>&1; then
    printf 'Upstream iOS build failed. See %s\n' "${LOG_FILE}" >&2
    exit 1
  fi

  cp "${IOS64_PREFIX}/lib/libsodium.a" "${DEVICE_OUTPUT}"
  lipo -create \
    "${IOS_SIMULATOR_ARM64_PREFIX}/lib/libsodium.a" \
    "${IOS_SIMULATOR_X86_64_PREFIX}/lib/libsodium.a" \
    -output "${SIMULATOR_OUTPUT}"
  popd >/dev/null

  xcrun ranlib -D "${DEVICE_OUTPUT}"
  xcrun ranlib -D "${SIMULATOR_OUTPUT}"
}

write_build_info() {
  local device_sha simulator_sha
  device_sha="$(sha256_file "${DEVICE_OUTPUT}")"
  simulator_sha="$(sha256_file "${SIMULATOR_OUTPUT}")"

  cat > "${BUILD_INFO_OUTPUT}" <<EOF2
{
  "libsodium_version": "${LIBSODIUM_VERSION}",
  "source_url": "${LIBSODIUM_URL}",
  "source_sha256": "${LIBSODIUM_SHA256}",
  "xcode_version": "${XCODE_VERSION}",
  "xcode_build_version": "${XCODE_BUILD_VERSION}",
  "iphoneos_sdk_version": "${IPHONEOS_SDK_VERSION}",
  "iphonesimulator_sdk_version": "${IPHONESIMULATOR_SDK_VERSION}",
  "min_ios_version": "${MIN_IOS_VERSION}",
  "build_variant": "full",
  "upstream_dist_build_script": "dist-build/apple-xcframework.sh",
  "upstream_functions_used": ["build_ios", "build_ios_simulator"],
  "upstream_overrides": ["--disable-shared", "--enable-static"],
  "device_archive": "$(basename "${DEVICE_OUTPUT}")",
  "device_sha256": "${device_sha}",
  "device_archs": ["arm64"],
  "simulator_archive": "$(basename "${SIMULATOR_OUTPUT}")",
  "simulator_sha256": "${simulator_sha}",
  "simulator_archs": ["arm64", "x86_64"]
}
EOF2
}

main() {
  ensure_commands
  download_archive
  detect_xcode_metadata

  mkdir -p "${WORK_ROOT}" "${PREBUILT_DIR}"
  build_archives_from_upstream "${WORK_ROOT}/src"

  write_build_info

  log "Created $(basename "${DEVICE_OUTPUT}"): $(lipo -info "${DEVICE_OUTPUT}")"
  log "Created $(basename "${SIMULATOR_OUTPUT}"): $(lipo -info "${SIMULATOR_OUTPUT}")"
  log "Wrote $(basename "${BUILD_INFO_OUTPUT}")"
}

main "$@"
