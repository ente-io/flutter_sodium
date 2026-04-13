#!/usr/bin/env bash

set -euo pipefail

# Use the immutable point release tarball here. Stable tarballs are intentionally
# mutable, which is useful for app build hooks but not ideal for checked-in
# artifacts that we want to regenerate deterministically.
#
# NDK r28c only provides Android 21+ sysroots for the ABIs we ship here, so the
# rebuilt shared libraries all target API 21 even for 32-bit ABIs.
LIBSODIUM_VERSION="${LIBSODIUM_VERSION:-1.0.21}"
LIBSODIUM_SHA256="${LIBSODIUM_SHA256:-9e4285c7a419e82dedb0be63a72eea357d6943bc3e28e6735bf600dd4883feaf}"
LIBSODIUM_URL="${LIBSODIUM_URL:-https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz}"
ANDROID_NDK_VERSION="${ANDROID_NDK_VERSION:-28.2.13676358}"
PAGE_ALIGNMENT_BYTES="16384"

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${BUILD_ROOT:-${ROOT_DIR}/build/android-libsodium}"
DOWNLOAD_DIR="${BUILD_ROOT}/downloads"
WORK_ROOT="${BUILD_ROOT}/work"
PREBUILT_DIR="${ROOT_DIR}/android/prebuilt"
JNI_LIBS_DIR="${ROOT_DIR}/android/src/main/jniLibs"

ARCHIVE_NAME="libsodium-${LIBSODIUM_VERSION}.tar.gz"
ARCHIVE_PATH="${LIBSODIUM_ARCHIVE_PATH:-${DOWNLOAD_DIR}/${ARCHIVE_NAME}}"
BUILD_INFO_OUTPUT="${PREBUILT_DIR}/libsodium-build-info.json"

ANDROID_HOME=""
NDK_ROOT=""
NDK_RELEASE_NAME=""
TOOLCHAIN_ROOT=""
TOOLCHAIN_BIN=""
LLVM_AR=""
LLVM_NM=""
LLVM_OBJDUMP=""
LLVM_RANLIB=""
LLVM_STRIP=""

ARMV7_OUTPUT="${JNI_LIBS_DIR}/armeabi-v7a/libsodium.so"
ARM64_OUTPUT="${JNI_LIBS_DIR}/arm64-v8a/libsodium.so"
X86_OUTPUT="${JNI_LIBS_DIR}/x86/libsodium.so"
X86_64_OUTPUT="${JNI_LIBS_DIR}/x86_64/libsodium.so"

log() {
  printf '==> %s\n' "$*"
}

ensure_commands() {
  local command
  for command in curl shasum tar make find awk sed strings grep; do
    if ! command -v "${command}" >/dev/null 2>&1; then
      printf 'Missing required command: %s\n' "${command}" >&2
      exit 1
    fi
  done
}

read_source_property() {
  local file="$1"
  local key="$2"
  awk -F ' = ' -v wanted="${key}" '$1 == wanted { print $2; exit }' "${file}"
}

detect_android_home() {
  local candidate
  for candidate in \
    "${ANDROID_HOME:-}" \
    "${ANDROID_SDK_ROOT:-}" \
    "${HOME}/Library/Android/sdk" \
    "/opt/homebrew/share/android-commandlinetools"
  do
    if [[ -n "${candidate}" && -d "${candidate}/ndk" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  printf 'Unable to locate Android SDK root. Set ANDROID_HOME or ANDROID_SDK_ROOT.\n' >&2
  exit 1
}

resolve_ndk_root() {
  local sdk_root="$1"

  if [[ -n "${ANDROID_NDK_HOME:-}" && -d "${ANDROID_NDK_HOME}" ]]; then
    printf '%s\n' "${ANDROID_NDK_HOME}"
    return 0
  fi

  if [[ -n "${ANDROID_NDK_ROOT:-}" && -d "${ANDROID_NDK_ROOT}" ]]; then
    printf '%s\n' "${ANDROID_NDK_ROOT}"
    return 0
  fi

  if [[ -d "${sdk_root}/ndk/${ANDROID_NDK_VERSION}" ]]; then
    printf '%s\n' "${sdk_root}/ndk/${ANDROID_NDK_VERSION}"
    return 0
  fi

  printf 'Unable to locate Android NDK %s under %s. Set ANDROID_NDK_HOME/ANDROID_NDK_ROOT or install that version.\n' \
    "${ANDROID_NDK_VERSION}" "${sdk_root}" >&2
  exit 1
}

resolve_toolchain_root() {
  local ndk_root="$1"
  local toolchain_root

  toolchain_root="$(find "${ndk_root}/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d | sort | head -n 1)"
  if [[ -z "${toolchain_root}" ]]; then
    printf 'Unable to locate LLVM toolchain under %s\n' "${ndk_root}" >&2
    exit 1
  fi

  printf '%s\n' "${toolchain_root}"
}

download_archive() {
  local fallback_archive="${ROOT_DIR}/build/ios-libsodium/downloads/${ARCHIVE_NAME}"

  mkdir -p "${DOWNLOAD_DIR}"

  if [[ ! -f "${ARCHIVE_PATH}" && -f "${fallback_archive}" ]]; then
    log "Reusing existing archive at ${fallback_archive}"
    cp "${fallback_archive}" "${ARCHIVE_PATH}"
  fi

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
  local abi="$2"
  local dist_build_script="$3"
  local built_library_path="$4"
  local source_root="$5"

  local source_dir
  source_dir="$(extract_source "${source_root}")"

  if [[ ! -x "${source_dir}/${dist_build_script}" ]]; then
    printf 'Unable to locate upstream build script: %s\n' "${source_dir}/${dist_build_script}" >&2
    exit 1
  fi

  log "Building ${name} via ${dist_build_script}"
  pushd "${source_dir}" >/dev/null
  # Pin binutils to the NDK toolchain so libtool doesn't fall back to macOS host tools.
  env \
    ANDROID_NDK_HOME="${NDK_ROOT}" \
    AR="${LLVM_AR}" \
    NDK_PLATFORM="android-21" \
    LIBSODIUM_FULL_BUILD="Y" \
    NM="${LLVM_NM}" \
    OBJDUMP="${LLVM_OBJDUMP}" \
    RANLIB="${LLVM_RANLIB}" \
    STRIP="${LLVM_STRIP}" \
    "${source_dir}/${dist_build_script}"
  popd >/dev/null

  if [[ ! -f "${source_dir}/${built_library_path}" ]]; then
    printf 'Unable to locate built library: %s\n' "${source_dir}/${built_library_path}" >&2
    exit 1
  fi

  mkdir -p "${JNI_LIBS_DIR}/${abi}"
  cp "${source_dir}/${built_library_path}" "${JNI_LIBS_DIR}/${abi}/libsodium.so"
}

verify_load_alignment() {
  local library_path="$1"

  if ! "${LLVM_OBJDUMP}" -p "${library_path}" | awk '/LOAD/{count++; if ($0 !~ /align 2\*\*14/) bad=1} END{exit !(count > 0 && bad != 1)}'; then
    printf 'Expected all LOAD segments in %s to use 16 KB alignment.\n' "${library_path}" >&2
    exit 1
  fi
}

verify_version_string() {
  local library_path="$1"

  if ! strings "${library_path}" | grep -Fx -- "${LIBSODIUM_VERSION}" >/dev/null 2>&1; then
    printf 'Unable to find libsodium version string %s in %s\n' "${LIBSODIUM_VERSION}" "${library_path}" >&2
    exit 1
  fi
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

write_build_info() {
  local armv7_sha arm64_sha x86_sha x86_64_sha

  armv7_sha="$(sha256_file "${ARMV7_OUTPUT}")"
  arm64_sha="$(sha256_file "${ARM64_OUTPUT}")"
  x86_sha="$(sha256_file "${X86_OUTPUT}")"
  x86_64_sha="$(sha256_file "${X86_64_OUTPUT}")"

  cat > "${BUILD_INFO_OUTPUT}" <<EOF2
{
  "libsodium_version": "${LIBSODIUM_VERSION}",
  "source_url": "${LIBSODIUM_URL}",
  "source_sha256": "${LIBSODIUM_SHA256}",
  "android_ndk_version": "${ANDROID_NDK_VERSION}",
  "android_ndk_release": "${NDK_RELEASE_NAME}",
  "llvm_prebuilt_host": "$(basename "${TOOLCHAIN_ROOT}")",
  "page_alignment_bytes": ${PAGE_ALIGNMENT_BYTES},
  "linker_flags": ["-Wl,-z,max-page-size=${PAGE_ALIGNMENT_BYTES}"],
  "build_variant": "full",
  "upstream_dist_build_scripts": [
    "dist-build/android-armv7-a.sh",
    "dist-build/android-armv8-a.sh",
    "dist-build/android-x86.sh",
    "dist-build/android-x86_64.sh"
  ],
  "abi_outputs": [
    {
      "abi": "armeabi-v7a",
      "android_api": 21,
      "library_path": "android/src/main/jniLibs/armeabi-v7a/libsodium.so",
      "sha256": "${armv7_sha}"
    },
    {
      "abi": "arm64-v8a",
      "android_api": 21,
      "library_path": "android/src/main/jniLibs/arm64-v8a/libsodium.so",
      "sha256": "${arm64_sha}"
    },
    {
      "abi": "x86",
      "android_api": 21,
      "library_path": "android/src/main/jniLibs/x86/libsodium.so",
      "sha256": "${x86_sha}"
    },
    {
      "abi": "x86_64",
      "android_api": 21,
      "library_path": "android/src/main/jniLibs/x86_64/libsodium.so",
      "sha256": "${x86_64_sha}"
    }
  ]
}
EOF2
}

main() {
  ensure_commands

  ANDROID_HOME="$(detect_android_home)"
  NDK_ROOT="$(resolve_ndk_root "${ANDROID_HOME}")"
  NDK_RELEASE_NAME="$(read_source_property "${NDK_ROOT}/source.properties" "Pkg.ReleaseName")"
  TOOLCHAIN_ROOT="$(resolve_toolchain_root "${NDK_ROOT}")"
  TOOLCHAIN_BIN="${TOOLCHAIN_ROOT}/bin"
  LLVM_AR="${TOOLCHAIN_BIN}/llvm-ar"
  LLVM_NM="${TOOLCHAIN_BIN}/llvm-nm"
  LLVM_OBJDUMP="${TOOLCHAIN_BIN}/llvm-objdump"
  LLVM_RANLIB="${TOOLCHAIN_BIN}/llvm-ranlib"
  LLVM_STRIP="${TOOLCHAIN_BIN}/llvm-strip"

  if [[ ! -x "${LLVM_AR}" || ! -x "${LLVM_NM}" || ! -x "${LLVM_OBJDUMP}" || ! -x "${LLVM_RANLIB}" || ! -x "${LLVM_STRIP}" ]]; then
    printf 'Unable to locate required LLVM binutils under %s\n' "${TOOLCHAIN_BIN}" >&2
    exit 1
  fi

  download_archive
  mkdir -p "${WORK_ROOT}" "${PREBUILT_DIR}"

  build_target \
    "Android armeabi-v7a" \
    "armeabi-v7a" \
    "dist-build/android-armv7-a.sh" \
    "libsodium-android-armv7-a/lib/libsodium.so" \
    "${WORK_ROOT}/armeabi-v7a/src"

  build_target \
    "Android arm64-v8a" \
    "arm64-v8a" \
    "dist-build/android-armv8-a.sh" \
    "libsodium-android-armv8-a+crypto/lib/libsodium.so" \
    "${WORK_ROOT}/arm64-v8a/src"

  build_target \
    "Android x86" \
    "x86" \
    "dist-build/android-x86.sh" \
    "libsodium-android-i686/lib/libsodium.so" \
    "${WORK_ROOT}/x86/src"

  build_target \
    "Android x86_64" \
    "x86_64" \
    "dist-build/android-x86_64.sh" \
    "libsodium-android-westmere/lib/libsodium.so" \
    "${WORK_ROOT}/x86_64/src"

  verify_load_alignment "${ARMV7_OUTPUT}"
  verify_load_alignment "${ARM64_OUTPUT}"
  verify_load_alignment "${X86_OUTPUT}"
  verify_load_alignment "${X86_64_OUTPUT}"

  verify_version_string "${ARMV7_OUTPUT}"
  verify_version_string "${ARM64_OUTPUT}"
  verify_version_string "${X86_OUTPUT}"
  verify_version_string "${X86_64_OUTPUT}"

  write_build_info

  log "Created $(basename "${ARMV7_OUTPUT}") for armeabi-v7a"
  log "Created $(basename "${ARM64_OUTPUT}") for arm64-v8a"
  log "Created $(basename "${X86_OUTPUT}") for x86"
  log "Created $(basename "${X86_64_OUTPUT}") for x86_64"
  log "Wrote $(basename "${BUILD_INFO_OUTPUT}")"
}

main "$@"
