import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'bindings/crypto_aead_bindings.dart';
import 'bindings/crypto_auth_bindings.dart';
import 'bindings/crypto_box_bindings.dart';
import 'bindings/crypto_core_bindings.dart';
import 'bindings/crypto_generichash_bindings.dart';
import 'bindings/crypto_hash_bindings.dart';
import 'bindings/crypto_kdf_bindings.dart';
import 'bindings/crypto_kx_bindings.dart';
import 'bindings/crypto_onetimeauth_bindings.dart';
import 'bindings/crypto_pwhash_bindings.dart';
import 'bindings/crypto_scalarmult_bindings.dart';
import 'bindings/crypto_secretbox_bindings.dart';
import 'bindings/crypto_secretstream_bindings.dart';
import 'bindings/crypto_shorthash_bindings.dart';
import 'bindings/crypto_sign_bindings.dart';
import 'bindings/crypto_stream_bindings.dart';
import 'bindings/randombytes_bindings.dart';
import 'bindings/sodium_bindings.dart';
import 'sodium_exception.dart';
import 'extensions.dart';
import 'detached_cipher.dart';
import 'init_push_result.dart';
import 'key_pair.dart';
import 'pull_result.dart';
import 'session_keys.dart';

/// The core flutter_sodium API mapping libsodium function to Dart equivalents.
class Sodium {
  static final _chacha20poly1305 = _CryptoAead.chacha20poly1305();
  static final _chacha20poly1305Ietf = _CryptoAead.chacha20poly1305Ietf();
  static final _xchacha20poly1305Ietf = _CryptoAead.xchacha20poly1305Ietf();
  static final _cryptoAuth = CryptoAuthBindings();
  static final _cryptoBox = CryptoBoxBindings();
  static final _cryptoCore = CryptoCoreBindings();
  static final _cryptoGenerichash = CryptoGenerichashBindings();
  static final _cryptoHash = CryptoHashBindings('crypto_hash');
  static final _cryptoKdf = CryptoKdfBindings();
  static final _cryptoKx = CryptoKxBindings();
  static final _cryptoOnetimeauth = CryptoOnetimeauthBindings();
  static final _cryptoPwhash = CryptoPwhashBindings();
  static final _cryptoScalarmult = CryptoScalarmultBindings();
  static final _cryptoSecretbox = CryptoSecretboxBindings();
  static final _cryptoSecretStream = CryptoSecretstreamBindings();
  static final _cryptoShorthash = CryptoShorthashBindings();
  static final _cryptoSign = CryptoSignBindings();
  static final _cryptoStream = CryptoStreamBindings();
  static final _randombytes = RandombytesBindings();
  static final _sodium = SodiumBindings();

  //
  // crypto_aead_chacha20poly1305
  //
  static int get cryptoAeadChacha20poly1305Keybytes =>
      _chacha20poly1305.keybytes;
  static int get cryptoAeadChacha20poly1305Nsecbytes =>
      _chacha20poly1305.nsecbytes;
  static int get cryptoAeadChacha20poly1305Npubbytes =>
      _chacha20poly1305.npubbytes;
  static int get cryptoAeadChacha20poly1305Abytes => _chacha20poly1305.abytes;
  static int get cryptoAeadChacha20poly1305MessagebytesMax =>
      _chacha20poly1305.messagebytesMax;

  static final cryptoAeadChacha20poly1305Encrypt = _chacha20poly1305.encrypt;
  static final cryptoAeadChacha20poly1305Decrypt = _chacha20poly1305.decrypt;
  static final cryptoAeadChacha20poly1305EncryptDetached =
      _chacha20poly1305.encryptDetached;
  static final cryptoAeadChacha20poly1305DecryptDetached =
      _chacha20poly1305.decryptDetached;
  static final cryptoAeadChacha20poly1305Keygen = _chacha20poly1305.keygen;

  //
  // crypto_aead_chacha20poly1305_ietf
  //
  static int get cryptoAeadChacha20poly1305IetfKeybytes =>
      _chacha20poly1305Ietf.keybytes;
  static int get cryptoAeadChacha20poly1305IetfNsecbytes =>
      _chacha20poly1305Ietf.nsecbytes;
  static int get cryptoAeadChacha20poly1305IetfNpubbytes =>
      _chacha20poly1305Ietf.npubbytes;
  static int get cryptoAeadChacha20poly1305IetfAbytes =>
      _chacha20poly1305Ietf.abytes;
  static int get cryptoAeadChacha20poly1305IetfMessagebytesMax =>
      _chacha20poly1305Ietf.messagebytesMax;

  static final cryptoAeadChacha20poly1305IetfEncrypt =
      _chacha20poly1305Ietf.encrypt;
  static final cryptoAeadChacha20poly1305IetfDecrypt =
      _chacha20poly1305Ietf.decrypt;
  static final cryptoAeadChacha20poly1305IetfEncryptDetached =
      _chacha20poly1305Ietf.encryptDetached;
  static final cryptoAeadChacha20poly1305IetfDecryptDetached =
      _chacha20poly1305Ietf.decryptDetached;
  static final cryptoAeadChacha20poly1305IetfKeygen =
      _chacha20poly1305Ietf.keygen;

  //
  // crypto_aead_xchacha20poly1305_ietf
  //
  static int get cryptoAeadXchacha20poly1305IetfKeybytes =>
      _xchacha20poly1305Ietf.keybytes;
  static int get cryptoAeadXchacha20poly1305IetfNsecbytes =>
      _xchacha20poly1305Ietf.nsecbytes;
  static int get cryptoAeadXchacha20poly1305IetfNpubbytes =>
      _xchacha20poly1305Ietf.npubbytes;
  static int get cryptoAeadXchacha20poly1305IetfAbytes =>
      _xchacha20poly1305Ietf.abytes;
  static int get cryptoAeadXchacha20poly1305IetfMessagebytesMax =>
      _xchacha20poly1305Ietf.messagebytesMax;

  static final cryptoAeadXchacha20poly1305IetfEncrypt =
      _xchacha20poly1305Ietf.encrypt;
  static final cryptoAeadXchacha20poly1305IetfDecrypt =
      _xchacha20poly1305Ietf.decrypt;
  static final cryptoAeadXchacha20poly1305IetfEncryptDetached =
      _xchacha20poly1305Ietf.encryptDetached;
  static final cryptoAeadXchacha20poly1305IetfDecryptDetached =
      _xchacha20poly1305Ietf.decryptDetached;
  static final cryptoAeadXchacha20poly1305IetfKeygen =
      _xchacha20poly1305Ietf.keygen;

  //
  // crypto_auth
  //
  static int get cryptoAuthBytes => _cryptoAuth.crypto_auth_bytes();
  static int get cryptoAuthKeybytes => _cryptoAuth.crypto_auth_keybytes();
  static String get cryptoAuthPrimitive =>
      _cryptoAuth.crypto_auth_primitive().toDartString();

  static Uint8List cryptoAuth(Uint8List i, Uint8List k) {
    RangeError.checkValueInInterval(k.length, cryptoAuthKeybytes,
        cryptoAuthKeybytes, 'k', 'Invalid length');

    final out0 = calloc<Uint8>(cryptoAuthBytes);
    final i0 = i.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoAuth
          .crypto_auth(out0, i0, i.length, k0)
          .mustSucceed('crypto_auth');

      return out0.toList(cryptoAuthBytes);
    } finally {
      calloc.free(out0);
      calloc.free(i0);
      calloc.free(k0);
    }
  }

  static bool cryptoAuthVerify(Uint8List h, Uint8List i, Uint8List k) {
    RangeError.checkValueInInterval(
        h.length, cryptoAuthBytes, cryptoAuthBytes, 'h', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoAuthKeybytes,
        cryptoAuthKeybytes, 'k', 'Invalid length');

    final h0 = h.toPointer();
    final i0 = i.toPointer();
    final k0 = k.toPointer();

    try {
      return _cryptoAuth.crypto_auth_verify(h0, i0, i.length, k0) == 0;
    } finally {
      calloc.free(h0);
      calloc.free(i0);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoAuthKeygen() {
    final k0 = calloc<Uint8>(cryptoAuthKeybytes);
    try {
      _cryptoAuth.crypto_auth_keygen(k0);
      return k0.toList(cryptoAuthKeybytes);
    } finally {
      calloc.free(k0);
    }
  }

  //
  // crypto_box
  //
  static int get cryptoBoxSeedbytes => _cryptoBox.crypto_box_seedbytes();
  static int get cryptoBoxPublickeybytes =>
      _cryptoBox.crypto_box_publickeybytes();
  static int get cryptoBoxSecretkeybytes =>
      _cryptoBox.crypto_box_secretkeybytes();
  static int get cryptoBoxNoncebytes => _cryptoBox.crypto_box_noncebytes();
  static int get cryptoBoxMacbytes => _cryptoBox.crypto_box_macbytes();
  static int get cryptoBoxMessagebytesMax =>
      _cryptoBox.crypto_box_messagebytes_max();
  static int get cryptoBoxSealbytes => _cryptoBox.crypto_box_sealbytes();
  static int get cryptoBoxBeforenmbytes =>
      _cryptoBox.crypto_box_beforenmbytes();
  static String get cryptoBoxPrimitive =>
      _cryptoBox.crypto_box_primitive().toDartString();

  static KeyPair cryptoBoxSeedKeypair(Uint8List seed) {
    RangeError.checkValueInInterval(seed.length, cryptoBoxSeedbytes,
        cryptoBoxSeedbytes, 'seed', 'Invalid length');
    final pk = calloc<Uint8>(cryptoBoxPublickeybytes);
    final sk = calloc<Uint8>(cryptoBoxSecretkeybytes);
    final seed0 = seed.toPointer();

    try {
      _cryptoBox
          .crypto_box_seed_keypair(pk, sk, seed0)
          .mustSucceed('crypto_box_seed_keypair');
      return KeyPair(
          pk: pk.toList(cryptoBoxPublickeybytes),
          sk: sk.toList(cryptoBoxSecretkeybytes));
    } finally {
      calloc.free(pk);
      calloc.free(sk);
      calloc.free(seed0);
    }
  }

  static KeyPair cryptoBoxKeypair() {
    final pk = calloc<Uint8>(cryptoBoxPublickeybytes);
    final sk = calloc<Uint8>(cryptoBoxSecretkeybytes);

    try {
      _cryptoBox.crypto_box_keypair(pk, sk).mustSucceed('crypto_box_keypair');
      return KeyPair(
          pk: pk.toList(cryptoBoxPublickeybytes),
          sk: sk.toList(cryptoBoxSecretkeybytes));
    } finally {
      calloc.free(pk);
      calloc.free(sk);
    }
  }

  static Uint8List cryptoBoxEasy(
      Uint8List m, Uint8List n, Uint8List pk, Uint8List sk) {
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final c = calloc<Uint8>(m.length + cryptoBoxMacbytes);
    final m0 = m.toPointer();
    final n0 = n.toPointer();
    final pk0 = pk.toPointer();
    final sk0 = sk.toPointer();

    try {
      _cryptoBox
          .crypto_box_easy(c, m0, m.length, n0, pk0, sk0)
          .mustSucceed('crypto_box_easy');

      return c.toList(m.length + cryptoBoxMacbytes);
    } finally {
      calloc.free(c);
      calloc.free(m0);
      calloc.free(n0);
      calloc.free(pk0);
      calloc.free(sk0);
    }
  }

  static Uint8List cryptoBoxOpenEasy(
      Uint8List c, Uint8List n, Uint8List pk, Uint8List sk) {
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final m = calloc<Uint8>(c.length - cryptoBoxMacbytes);
    final c0 = c.toPointer();
    final n0 = n.toPointer();
    final pk0 = pk.toPointer();
    final sk0 = sk.toPointer();

    try {
      _cryptoBox
          .crypto_box_open_easy(m, c0, c.length, n0, pk0, sk0)
          .mustSucceed('crypto_box_open_easy');

      return m.toList(c.length - cryptoBoxMacbytes);
    } finally {
      calloc.free(m);
      calloc.free(c0);
      calloc.free(n0);
      calloc.free(pk0);
      calloc.free(sk0);
    }
  }

  static DetachedCipher cryptoBoxDetached(
      Uint8List m, Uint8List n, Uint8List pk, Uint8List sk) {
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final c = calloc<Uint8>(m.length);
    final mac = calloc<Uint8>(cryptoBoxMacbytes);
    final m0 = m.toPointer();
    final n0 = n.toPointer();
    final pk0 = pk.toPointer();
    final sk0 = sk.toPointer();

    try {
      _cryptoBox
          .crypto_box_detached(c, mac, m0, m.length, n0, pk0, sk0)
          .mustSucceed('crypto_box_detached');

      return DetachedCipher(
          c: c.toList(m.length), mac: mac.toList(cryptoBoxMacbytes));
    } finally {
      calloc.free(c);
      calloc.free(mac);
      calloc.free(m0);
      calloc.free(n0);
      calloc.free(pk0);
      calloc.free(sk0);
    }
  }

  static Uint8List cryptoBoxOpenDetached(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List pk, Uint8List sk) {
    RangeError.checkValueInInterval(mac.length, cryptoBoxMacbytes,
        cryptoBoxMacbytes, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final m = calloc<Uint8>(c.length);
    final mac0 = mac.toPointer();
    final c0 = c.toPointer();
    final n0 = n.toPointer();
    final pk0 = pk.toPointer();
    final sk0 = sk.toPointer();

    try {
      _cryptoBox
          .crypto_box_open_detached(m, c0, mac0, c.length, n0, pk0, sk0)
          .mustSucceed('crypto_box_open_detached');

      return m.toList(c.length);
    } finally {
      calloc.free(m);
      calloc.free(mac0);
      calloc.free(c0);
      calloc.free(n0);
      calloc.free(pk0);
      calloc.free(sk0);
    }
  }

  static Uint8List cryptoBoxBeforenm(Uint8List pk, Uint8List sk) {
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final k = calloc<Uint8>(cryptoBoxBeforenmbytes);
    final pk0 = pk.toPointer();
    final sk0 = sk.toPointer();
    try {
      _cryptoBox
          .crypto_box_beforenm(k, pk0, sk0)
          .mustSucceed('crypto_box_beforenm');

      return k.toList(cryptoBoxBeforenmbytes);
    } finally {
      calloc.free(k);
      calloc.free(pk0);
      calloc.free(sk0);
    }
  }

  static Uint8List cryptoBoxEasyAfternm(Uint8List m, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoBoxBeforenmbytes,
        cryptoBoxBeforenmbytes, 'k', 'Invalid length');

    final c = calloc<Uint8>(m.length + cryptoBoxMacbytes);
    final m0 = m.toPointer();
    final n0 = n.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoBox
          .crypto_box_easy_afternm(c, m0, m.length, n0, k0)
          .mustSucceed('crypto_box_easy_afternm');

      return c.toList(m.length + cryptoBoxMacbytes);
    } finally {
      calloc.free(c);
      calloc.free(m0);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoBoxOpenEasyAfternm(
      Uint8List c, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoBoxBeforenmbytes,
        cryptoBoxBeforenmbytes, 'k', 'Invalid length');

    final m = calloc<Uint8>(c.length - cryptoBoxMacbytes);
    final c0 = c.toPointer();
    final n0 = n.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoBox
          .crypto_box_open_easy_afternm(m, c0, c.length, n0, k0)
          .mustSucceed('crypto_box_open_easy_afternm');

      return m.toList(c.length - cryptoBoxMacbytes);
    } finally {
      calloc.free(m);
      calloc.free(c0);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static DetachedCipher cryptoBoxDetachedAfternm(
      Uint8List m, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoBoxBeforenmbytes,
        cryptoBoxBeforenmbytes, 'k', 'Invalid length');

    final c = calloc<Uint8>(m.length);
    final mac = calloc<Uint8>(cryptoBoxMacbytes);
    final m0 = m.toPointer();
    final n0 = n.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoBox
          .crypto_box_detached_afternm(c, mac, m0, m.length, n0, k0)
          .mustSucceed('crypto_box_detached_afternm');

      return DetachedCipher(
          c: c.toList(m.length), mac: mac.toList(cryptoBoxMacbytes));
    } finally {
      calloc.free(c);
      calloc.free(mac);
      calloc.free(m0);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoBoxOpenDetachedAfternm(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(mac.length, cryptoBoxMacbytes,
        cryptoBoxMacbytes, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(n.length, cryptoBoxNoncebytes,
        cryptoBoxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoBoxBeforenmbytes,
        cryptoBoxBeforenmbytes, 'k', 'Invalid length');

    final m = calloc<Uint8>(c.length);
    final mac0 = mac.toPointer();
    final c0 = c.toPointer();
    final n0 = n.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoBox
          .crypto_box_open_detached_afternm(m, c0, mac0, c.length, n0, k0)
          .mustSucceed('crypto_box_open_detached_afternm');

      return m.toList(c.length);
    } finally {
      calloc.free(m);
      calloc.free(mac0);
      calloc.free(c0);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoBoxSeal(Uint8List m, Uint8List pk) {
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');

    final c = calloc<Uint8>(m.length + cryptoBoxSealbytes);
    final m0 = m.toPointer();
    final pk0 = pk.toPointer();

    try {
      _cryptoBox
          .crypto_box_seal(c, m0, m.length, pk0)
          .mustSucceed('crypto_box_seal');

      return c.toList(m.length + cryptoBoxSealbytes);
    } finally {
      calloc.free(c);
      calloc.free(m0);
      calloc.free(pk0);
    }
  }

  static Uint8List cryptoBoxSealOpen(Uint8List c, Uint8List pk, Uint8List sk) {
    RangeError.checkValueInInterval(pk.length, cryptoBoxPublickeybytes,
        cryptoBoxPublickeybytes, 'pk', 'Invalid length');
    RangeError.checkValueInInterval(sk.length, cryptoBoxSecretkeybytes,
        cryptoBoxSecretkeybytes, 'sk', 'Invalid length');

    final m = calloc<Uint8>(c.length - cryptoBoxSealbytes);
    final c0 = c.toPointer();
    final pk0 = pk.toPointer();
    final sk0 = sk.toPointer();

    try {
      _cryptoBox
          .crypto_box_seal_open(m, c0, c.length, pk0, sk0)
          .mustSucceed('crypto_box_seal_open');

      return m.toList(c.length - cryptoBoxSealbytes);
    } finally {
      calloc.free(m);
      calloc.free(c0);
      calloc.free(pk0);
      calloc.free(sk0);
    }
  }

  //
  // crypto_core
  //
  static int get cryptoCoreHchacha20Outputbytes =>
      _cryptoCore.crypto_core_hchacha20_outputbytes();
  static int get cryptoCoreHchacha20Inputbytes =>
      _cryptoCore.crypto_core_hchacha20_inputbytes();
  static int get cryptoCoreHchacha20Keybytes =>
      _cryptoCore.crypto_core_hchacha20_keybytes();
  static int get cryptoCoreHchacha20Constbytes =>
      _cryptoCore.crypto_core_hchacha20_constbytes();

  static Uint8List cryptoCoreHchacha20(Uint8List i, Uint8List k, Uint8List? c) {
    RangeError.checkValueInInterval(i.length, cryptoCoreHchacha20Inputbytes,
        cryptoCoreHchacha20Inputbytes, 'i', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoCoreHchacha20Keybytes,
        cryptoCoreHchacha20Keybytes, 'k', 'Invalid length');
    if (c != null) {
      RangeError.checkValueInInterval(c.length, cryptoCoreHchacha20Constbytes,
          cryptoCoreHchacha20Constbytes, 'c', 'Invalid length');
    }
    final out = calloc<Uint8>(cryptoCoreHchacha20Outputbytes);
    final i0 = i.toPointer();
    final k0 = k.toPointer();
    final c0 = c?.toPointer() ?? nullptr;

    try {
      _cryptoCore
          .crypto_core_hchacha20(out, i0, k0, c0)
          .mustSucceed('crypto_core_hchacha20');
      return out.toList(cryptoCoreHchacha20Outputbytes);
    } finally {
      calloc.free(out);
      calloc.free(i0);
      calloc.free(k0);
      if (c0 != nullptr) {
        calloc.free(c0);
      }
    }
  }

  static int get cryptoCoreHsalsa20Outputbytes =>
      _cryptoCore.crypto_core_hsalsa20_outputbytes();
  static int get cryptoCoreHsalsa20Inputbytes =>
      _cryptoCore.crypto_core_hsalsa20_inputbytes();
  static int get cryptoCoreHsalsa20Keybytes =>
      _cryptoCore.crypto_core_hsalsa20_keybytes();
  static int get cryptoCoreHsalsa20Constbytes =>
      _cryptoCore.crypto_core_hsalsa20_constbytes();

  static Uint8List cryptoCoreHsalsa20(Uint8List i, Uint8List k, Uint8List? c) {
    RangeError.checkValueInInterval(i.length, cryptoCoreHsalsa20Inputbytes,
        cryptoCoreHsalsa20Inputbytes, 'i', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoCoreHsalsa20Keybytes,
        cryptoCoreHsalsa20Keybytes, 'k', 'Invalid length');
    if (c != null) {
      RangeError.checkValueInInterval(c.length, cryptoCoreHsalsa20Constbytes,
          cryptoCoreHsalsa20Constbytes, 'c', 'Invalid length');
    }
    final out = calloc<Uint8>(cryptoCoreHsalsa20Outputbytes);
    final i0 = i.toPointer();
    final k0 = k.toPointer();
    final c0 = c?.toPointer() ?? nullptr;

    try {
      _cryptoCore
          .crypto_core_hsalsa20(out, i0, k0, c0)
          .mustSucceed('crypto_core_hsalsa20');
      return out.toList(cryptoCoreHsalsa20Outputbytes);
    } finally {
      calloc.free(out);
      calloc.free(i0);
      calloc.free(k0);
      if (c0 != nullptr) {
        calloc.free(c0);
      }
    }
  }

  //
  // crypto_generichash
  //
  static int get cryptoGenerichashBytesMin =>
      _cryptoGenerichash.crypto_generichash_bytes_min();
  static int get cryptoGenerichashBytesMax =>
      _cryptoGenerichash.crypto_generichash_bytes_max();
  static int get cryptoGenerichashBytes =>
      _cryptoGenerichash.crypto_generichash_bytes();
  static int get cryptoGenerichashKeybytesMin =>
      _cryptoGenerichash.crypto_generichash_keybytes_min();
  static int get cryptoGenerichashKeybytesMax =>
      _cryptoGenerichash.crypto_generichash_keybytes_max();
  static int get cryptoGenerichashKeybytes =>
      _cryptoGenerichash.crypto_generichash_keybytes();
  static String get cryptoGenerichashPrimitive =>
      _cryptoGenerichash.crypto_generichash_primitive().toDartString();
  static int get cryptoGenerichashStatebytes =>
      _cryptoGenerichash.crypto_generichash_statebytes();

  static Uint8List cryptoGenerichash(int outlen, Uint8List i, Uint8List? key) {
    RangeError.checkValueInInterval(
        outlen, cryptoGenerichashBytesMin, cryptoGenerichashBytesMax);
    if (key != null) {
      RangeError.checkValueInInterval(key.length, cryptoGenerichashKeybytesMin,
          cryptoGenerichashKeybytesMax, 'key', 'Invalid length');
    }

    final out = calloc<Uint8>(outlen);
    final i0 = i.toPointer();
    final key0 = key?.toPointer() ?? nullptr;

    try {
      _cryptoGenerichash
          .crypto_generichash(out, outlen, i0, i.length, key0, key?.length ?? 0)
          .mustSucceed('crypto_generichash');
      return out.toList(outlen);
    } finally {
      calloc.free(out);
      calloc.free(i0);
      if (key0 != nullptr) {
        calloc.free(key0);
      }
    }
  }

  static Pointer<Uint8> cryptoGenerichashInit(Uint8List? key, int outlen) {
    if (key != null) {
      RangeError.checkValueInInterval(key.length, cryptoGenerichashKeybytesMin,
          cryptoGenerichashKeybytesMax, 'key', 'Invalid length');
    }
    RangeError.checkValueInInterval(
        outlen, cryptoGenerichashBytesMin, cryptoGenerichashBytesMax);

    final state = calloc<Uint8>(cryptoGenerichashStatebytes);
    final key0 = key?.toPointer() ?? nullptr;

    try {
      _cryptoGenerichash
          .crypto_generichash_init(state, key0, key?.length ?? 0, outlen)
          .mustSucceed('crypto_generichash_init');
      return state;
    } finally {
      if (key0 != nullptr) {
        calloc.free(key0);
      }
    }
  }

  static void cryptoGenerichashUpdate(Pointer<Uint8> state, Uint8List i) {
    final i0 = i.toPointer();

    try {
      _cryptoGenerichash
          .crypto_generichash_update(state, i0, i.length)
          .mustSucceed('crypto_generichash_update');
    } finally {
      calloc.free(i0);
    }
  }

  static Uint8List cryptoGenerichashFinal(Pointer<Uint8> state, int outlen) {
    RangeError.checkValueInInterval(
        outlen, cryptoGenerichashBytesMin, cryptoGenerichashBytesMax);

    final out = calloc<Uint8>(outlen);

    try {
      _cryptoGenerichash
          .crypto_generichash_final(state, out, outlen)
          .mustSucceed('crypto_generichash_final');
      return out.toList(outlen);
    } finally {
      // note: caller is responsible for freeing state
      calloc.free(out);
    }
  }

  static Uint8List cryptoGenerichashKeygen() {
    final k = calloc<Uint8>(cryptoGenerichashKeybytes);
    try {
      _cryptoGenerichash.crypto_generichash_keygen(k);
      return k.toList(cryptoGenerichashKeybytes);
    } finally {
      calloc.free(k);
    }
  }

  //
  // crypto_hash
  //
  static int get cryptoHashBytes => _cryptoHash.bytes();
  static String get cryptoHashPrimitive =>
      _cryptoHash.primitive().toDartString();
  static Uint8List cryptoHash(Uint8List i) {
    final out = calloc<Uint8>(cryptoHashBytes);
    final i0 = i.toPointer();
    try {
      _cryptoHash.hash(out, i0, i.length).mustSucceed('crypto_hash');
      return out.toList(cryptoHashBytes);
    } finally {
      calloc.free(out);
      calloc.free(i0);
    }
  }

  //
  // crypto_kdf
  //
  static int get cryptoKdfBytesMin => _cryptoKdf.crypto_kdf_bytes_min();
  static int get cryptoKdfBytesMax => _cryptoKdf.crypto_kdf_bytes_max();
  static int get cryptoKdfContextbytes => _cryptoKdf.crypto_kdf_contextbytes();
  static int get cryptoKdfKeybytes => _cryptoKdf.crypto_kdf_keybytes();
  static String get cryptoKdfPrimitive =>
      _cryptoKdf.crypto_kdf_primitive().toDartString();

  static Uint8List cryptoKdfDeriveFromKey(
      int subkeyLen, int subkeyId, Uint8List ctx, Uint8List key) {
    RangeError.checkValueInInterval(
        subkeyLen, cryptoKdfBytesMin, cryptoKdfBytesMax, 'subkeyLen');
    RangeError.checkValueInInterval(subkeyId, 0, (2 ^ 64) - 1, 'subkeyId');
    RangeError.checkValueInInterval(ctx.length, cryptoKdfContextbytes,
        cryptoKdfContextbytes, 'ctx', 'Invalid length');
    RangeError.checkValueInInterval(key.length, cryptoKdfKeybytes,
        cryptoKdfKeybytes, 'key', 'Invalid length');

    final subkey = calloc<Uint8>(subkeyLen);
    final ctx0 = ctx.toPointer();
    final key0 = key.toPointer();

    try {
      _cryptoKdf
          .crypto_kdf_derive_from_key(subkey, subkeyLen, subkeyId, ctx0, key0)
          .mustSucceed('crypto_kdf_derive_from_key');
      return subkey.toList(subkeyLen);
    } finally {
      calloc.free(subkey);
      calloc.free(ctx0);
      calloc.free(key0);
    }
  }

  static Uint8List cryptoKdfKeygen() {
    final k = calloc<Uint8>(cryptoKdfKeybytes);
    try {
      _cryptoKdf.crypto_kdf_keygen(k);
      return k.toList(cryptoKdfKeybytes);
    } finally {
      calloc.free(k);
    }
  }

  //
  // crypto_kx
  //
  static int get cryptoKxPublickeybytes => _cryptoKx.crypto_kx_publickeybytes();
  static int get cryptoKxSecretkeybytes => _cryptoKx.crypto_kx_secretkeybytes();
  static int get cryptoKxSeedbytes => _cryptoKx.crypto_kx_seedbytes();
  static int get cryptoKxSessionkeybytes =>
      _cryptoKx.crypto_kx_sessionkeybytes();
  static String get cryptoKxPrimitive =>
      _cryptoKx.crypto_kx_primitive().toDartString();

  static KeyPair cryptoKxSeedKeypair(Uint8List seed) {
    RangeError.checkValueInInterval(seed.length, cryptoKxSeedbytes,
        cryptoKxSeedbytes, 'seed', 'Invalid length');
    final pk = calloc<Uint8>(cryptoKxPublickeybytes);
    final sk = calloc<Uint8>(cryptoKxSecretkeybytes);
    final seed0 = seed.toPointer();

    try {
      _cryptoKx
          .crypto_kx_seed_keypair(pk, sk, seed0)
          .mustSucceed('crypto_kx_seed_keypair');
      return KeyPair(
          pk: pk.toList(cryptoKxPublickeybytes),
          sk: sk.toList(cryptoKxSecretkeybytes));
    } finally {
      calloc.free(pk);
      calloc.free(sk);
      calloc.free(seed0);
    }
  }

  static KeyPair cryptoKxKeypair() {
    final pk = calloc<Uint8>(cryptoKxPublickeybytes);
    final sk = calloc<Uint8>(cryptoKxSecretkeybytes);

    try {
      _cryptoKx.crypto_kx_keypair(pk, sk).mustSucceed('crypto_kx_keypair');
      return KeyPair(
          pk: pk.toList(cryptoKxPublickeybytes),
          sk: sk.toList(cryptoKxSecretkeybytes));
    } finally {
      calloc.free(pk);
      calloc.free(sk);
    }
  }

  static SessionKeys cryptoKxClientSessionKeys(
      Uint8List clientPk, Uint8List clientSk, Uint8List serverPk) {
    RangeError.checkValueInInterval(clientPk.length, cryptoKxPublickeybytes,
        cryptoKxPublickeybytes, 'clientPk', 'Invalid length');
    RangeError.checkValueInInterval(clientSk.length, cryptoKxSecretkeybytes,
        cryptoKxSecretkeybytes, 'clientSk', 'Invalid length');
    RangeError.checkValueInInterval(serverPk.length, cryptoKxPublickeybytes,
        cryptoKxPublickeybytes, 'serverPk', 'Invalid length');

    final rx = calloc<Uint8>(cryptoKxSessionkeybytes);
    final tx = calloc<Uint8>(cryptoKxSessionkeybytes);
    final clientPk0 = clientPk.toPointer();
    final clientSk0 = clientSk.toPointer();
    final serverPk0 = serverPk.toPointer();

    try {
      _cryptoKx
          .crypto_kx_client_session_keys(
              rx, tx, clientPk0, clientSk0, serverPk0)
          .mustSucceed('crypto_kx_client_session_keys');

      return SessionKeys(
          rx: rx.toList(cryptoKxSessionkeybytes),
          tx: tx.toList(cryptoKxSessionkeybytes));
    } finally {
      calloc.free(rx);
      calloc.free(tx);
      calloc.free(clientPk0);
      calloc.free(clientSk0);
      calloc.free(serverPk0);
    }
  }

  static SessionKeys cryptoKxServerSessionKeys(
      Uint8List serverPk, Uint8List serverSk, Uint8List clientPk) {
    RangeError.checkValueInInterval(serverPk.length, cryptoKxPublickeybytes,
        cryptoKxPublickeybytes, 'serverPk', 'Invalid length');
    RangeError.checkValueInInterval(serverSk.length, cryptoKxSecretkeybytes,
        cryptoKxSecretkeybytes, 'serverSk', 'Invalid length');
    RangeError.checkValueInInterval(clientPk.length, cryptoKxPublickeybytes,
        cryptoKxPublickeybytes, 'clientPk', 'Invalid length');

    final rx = calloc<Uint8>(cryptoKxSessionkeybytes);
    final tx = calloc<Uint8>(cryptoKxSessionkeybytes);
    final serverPk0 = serverPk.toPointer();
    final serverSk0 = serverSk.toPointer();
    final clientPk0 = clientPk.toPointer();

    try {
      _cryptoKx
          .crypto_kx_server_session_keys(
              rx, tx, serverPk0, serverSk0, clientPk0)
          .mustSucceed('crypto_kx_server_session_keys');

      return SessionKeys(
          rx: rx.toList(cryptoKxSessionkeybytes),
          tx: tx.toList(cryptoKxSessionkeybytes));
    } finally {
      calloc.free(rx);
      calloc.free(tx);
      calloc.free(serverPk0);
      calloc.free(serverSk0);
      calloc.free(clientPk0);
    }
  }

  //
  // crypto_onetimeauth
  //
  static int get cryptoOnetimeauthStatebytes =>
      _cryptoOnetimeauth.crypto_onetimeauth_statebytes();
  static int get cryptoOnetimeauthBytes =>
      _cryptoOnetimeauth.crypto_onetimeauth_bytes();
  static int get cryptoOnetimeauthKeybytes =>
      _cryptoOnetimeauth.crypto_onetimeauth_keybytes();
  static String get cryptoOnetimeauthPrimitive =>
      _cryptoOnetimeauth.crypto_onetimeauth_primitive().toDartString();

  static Uint8List cryptoOnetimeauth(Uint8List i, Uint8List k) {
    RangeError.checkValueInInterval(k.length, cryptoOnetimeauthKeybytes,
        cryptoOnetimeauthKeybytes, 'k', 'Invalid length');

    final out = calloc<Uint8>(cryptoOnetimeauthBytes);
    final i0 = i.toPointer();
    final k0 = k.toPointer();
    try {
      _cryptoOnetimeauth
          .crypto_onetimeauth(out, i0, i.length, k0)
          .mustSucceed('crypto_onetimeauth');
      return out.toList(cryptoOnetimeauthBytes);
    } finally {
      calloc.free(out);
      calloc.free(i0);
      calloc.free(k0);
    }
  }

  static bool cryptoOnetimeauthVerify(Uint8List h, Uint8List i, Uint8List k) {
    RangeError.checkValueInInterval(h.length, cryptoOnetimeauthBytes,
        cryptoOnetimeauthBytes, 'h', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoOnetimeauthKeybytes,
        cryptoOnetimeauthKeybytes, 'k', 'Invalid length');

    final h0 = h.toPointer();
    final i0 = i.toPointer();
    final k0 = k.toPointer();
    try {
      return _cryptoOnetimeauth.crypto_onetimeauth_verify(
              h0, i0, i.length, k0) ==
          0;
    } finally {
      calloc.free(h0);
      calloc.free(i0);
      calloc.free(k0);
    }
  }

  static Pointer<Uint8> cryptoOnetimeauthInit(Uint8List key) {
    RangeError.checkValueInInterval(key.length, cryptoOnetimeauthKeybytes,
        cryptoOnetimeauthKeybytes, 'key', 'Invalid length');

    final state = calloc<Uint8>(cryptoOnetimeauthStatebytes);
    final k = key.toPointer();
    try {
      _cryptoOnetimeauth
          .crypto_onetimeauth_init(state, k)
          .mustSucceed('crypto_onetimeauth_init');
      return state;
    } finally {
      calloc.free(k);
    }
  }

  static void cryptoOnetimeauthUpdate(Pointer<Uint8> state, Uint8List i) {
    final i0 = i.toPointer();
    try {
      _cryptoOnetimeauth
          .crypto_onetimeauth_update(state, i0, i.length)
          .mustSucceed('crypto_onetimeauth_update');
    } finally {
      calloc.free(i0);
    }
  }

  static Uint8List cryptoOnetimeauthFinal(Pointer<Uint8> state) {
    final out = calloc<Uint8>(cryptoOnetimeauthBytes);
    try {
      _cryptoOnetimeauth.crypto_onetimeauth_final(state, out);
      return out.toList(cryptoOnetimeauthBytes);
    } finally {
      calloc.free(out);
    }
  }

  static Uint8List cryptoOnetimeauthKeygen() {
    final k = calloc<Uint8>(cryptoOnetimeauthKeybytes);
    try {
      _cryptoOnetimeauth.crypto_onetimeauth_keygen(k);
      return k.toList(cryptoOnetimeauthKeybytes);
    } finally {
      calloc.free(k);
    }
  }

  //
  // crypto_pwhash
  //
  static int get cryptoPwhashAlgArgon2i13 =>
      _cryptoPwhash.crypto_pwhash_alg_argon2i13();
  static int get cryptoPwhashAlgArgon2id13 =>
      _cryptoPwhash.crypto_pwhash_alg_argon2id13();
  static int get cryptoPwhashAlgDefault =>
      _cryptoPwhash.crypto_pwhash_alg_default();
  static int get cryptoPwhashBytesMin =>
      _cryptoPwhash.crypto_pwhash_bytes_min();
  static int get cryptoPwhashBytesMax =>
      _cryptoPwhash.crypto_pwhash_bytes_max();
  static int get cryptoPwhashPasswdMin =>
      _cryptoPwhash.crypto_pwhash_passwd_min();
  static int get cryptoPwhashPasswdMax =>
      _cryptoPwhash.crypto_pwhash_passwd_max();
  static int get cryptoPwhashSaltbytes =>
      _cryptoPwhash.crypto_pwhash_saltbytes();
  static int get cryptoPwhashStrbytes => _cryptoPwhash.crypto_pwhash_strbytes();
  static String get cryptoPwhashStrprefix =>
      _cryptoPwhash.crypto_pwhash_strprefix().toDartString();
  static int get cryptoPwhashOpslimitMin =>
      _cryptoPwhash.crypto_pwhash_opslimit_min();
  static int get cryptoPwhashOpslimitMax =>
      _cryptoPwhash.crypto_pwhash_opslimit_max();
  static int get cryptoPwhashMemlimitMin =>
      _cryptoPwhash.crypto_pwhash_memlimit_min();
  static int get cryptoPwhashMemlimitMax =>
      _cryptoPwhash.crypto_pwhash_memlimit_max();
  static int get cryptoPwhashArgon2iOpslimitMin =>
      _cryptoPwhash.crypto_pwhash_argon2i_opslimit_min();
  static int get cryptoPwhashArgon2iOpslimitMax =>
      _cryptoPwhash.crypto_pwhash_argon2i_opslimit_max();
  static int get cryptoPwhashArgon2iMemlimitMin =>
      _cryptoPwhash.crypto_pwhash_argon2i_memlimit_min();
  static int get cryptoPwhashArgon2iMemlimitMax =>
      _cryptoPwhash.crypto_pwhash_argon2i_memlimit_max();
  static int get cryptoPwhashOpslimitInteractive =>
      _cryptoPwhash.crypto_pwhash_opslimit_interactive();
  static int get cryptoPwhashMemlimitInteractive =>
      _cryptoPwhash.crypto_pwhash_memlimit_interactive();
  static int get cryptoPwhashOpslimitModerate =>
      _cryptoPwhash.crypto_pwhash_opslimit_moderate();
  static int get cryptoPwhashMemlimitModerate =>
      _cryptoPwhash.crypto_pwhash_memlimit_moderate();
  static int get cryptoPwhashOpslimitSensitive =>
      _cryptoPwhash.crypto_pwhash_opslimit_sensitive();
  static int get cryptoPwhashMemlimitSensitive =>
      _cryptoPwhash.crypto_pwhash_memlimit_sensitive();

  static String get cryptoPwhashPrimitive =>
      _cryptoPwhash.crypto_pwhash_primitive().toDartString();

  static Uint8List cryptoPwhash(int outlen, Uint8List passwd, Uint8List salt,
      int opslimit, int memlimit, int alg) {
    RangeError.checkValueInInterval(
        outlen, cryptoPwhashBytesMin, cryptoPwhashBytesMax, 'outlen');
    RangeError.checkValueInInterval(passwd.length, cryptoPwhashPasswdMin,
        cryptoPwhashPasswdMax, 'passwd', 'Invalid length');
    RangeError.checkValueInInterval(salt.length, cryptoPwhashSaltbytes,
        cryptoPwhashSaltbytes, 'salt', 'Invalid length');
    if (alg == cryptoPwhashAlgArgon2i13) {
      RangeError.checkValueInInterval(opslimit, cryptoPwhashArgon2iOpslimitMin,
          cryptoPwhashArgon2iOpslimitMax, 'opslimit');
      RangeError.checkValueInInterval(memlimit, cryptoPwhashArgon2iMemlimitMin,
          cryptoPwhashArgon2iMemlimitMax, 'memlimit');
    } else {
      RangeError.checkValueInInterval(opslimit, cryptoPwhashOpslimitMin,
          cryptoPwhashOpslimitMax, 'opslimit');
      RangeError.checkValueInInterval(memlimit, cryptoPwhashMemlimitMin,
          cryptoPwhashMemlimitMax, 'memlimit');
    }
    RangeError.checkValueInInterval(
        alg, cryptoPwhashAlgArgon2i13, cryptoPwhashAlgArgon2id13, 'alg');

    final out = calloc<Uint8>(outlen);
    final passwd0 = passwd.toPointer();
    final salt0 = salt.toPointer();
    try {
      _cryptoPwhash
          .crypto_pwhash(out, outlen, passwd0, passwd.length, salt0, opslimit,
              memlimit, alg)
          .mustSucceed('crypto_pwhash');

      return out.toList(outlen);
    } finally {
      calloc.free(out);
      calloc.free(passwd0);
      calloc.free(salt0);
    }
  }

  static Uint8List cryptoPwhashStr(
      Uint8List passwd, int opslimit, int memlimit) {
    RangeError.checkValueInInterval(passwd.length, cryptoPwhashPasswdMin,
        cryptoPwhashPasswdMax, 'passwd', 'Invalid length');
    RangeError.checkValueInInterval(
        opslimit, cryptoPwhashOpslimitMin, cryptoPwhashOpslimitMax, 'opslimit');
    RangeError.checkValueInInterval(
        memlimit, cryptoPwhashMemlimitMin, cryptoPwhashMemlimitMax, 'memlimit');

    final out = calloc<Uint8>(cryptoPwhashStrbytes);
    final passwd0 = passwd.toPointer();
    try {
      _cryptoPwhash
          .crypto_pwhash_str(out, passwd0, passwd.length, opslimit, memlimit)
          .mustSucceed('crypto_pwhash_str');
      return out.toNullTerminatedList(cryptoPwhashStrbytes);
    } finally {
      calloc.free(out);
      calloc.free(passwd0);
    }
  }

  static Uint8List cryptoPwhashStrAlg(
      Uint8List passwd, int opslimit, int memlimit, int alg) {
    RangeError.checkValueInInterval(passwd.length, cryptoPwhashPasswdMin,
        cryptoPwhashPasswdMax, 'passwd', 'Invalid length');
    RangeError.checkValueInInterval(
        opslimit, cryptoPwhashOpslimitMin, cryptoPwhashOpslimitMax, 'opslimit');
    RangeError.checkValueInInterval(
        memlimit, cryptoPwhashMemlimitMin, cryptoPwhashMemlimitMax, 'memlimit');
    RangeError.checkValueInInterval(
        alg, cryptoPwhashAlgArgon2i13, cryptoPwhashAlgArgon2id13, 'alg');

    final out = calloc<Uint8>(cryptoPwhashStrbytes);
    final passwd0 = passwd.toPointer();
    try {
      _cryptoPwhash
          .crypto_pwhash_str_alg(
              out, passwd0, passwd.length, opslimit, memlimit, alg)
          .mustSucceed('crypto_pwhash_str_alg');
      return out.toNullTerminatedList(cryptoPwhashStrbytes);
    } finally {
      calloc.free(out);
      calloc.free(passwd0);
    }
  }

  static int cryptoPwhashStrVerify(Uint8List str, Uint8List passwd) {
    RangeError.checkValueInInterval(
        str.length, 1, cryptoPwhashStrbytes, 'str', 'Invalid length');
    RangeError.checkValueInInterval(passwd.length, cryptoPwhashPasswdMin,
        cryptoPwhashPasswdMax, 'passwd', 'Invalid length');

    // make sure str is null terminated
    final str0 =
        str.toNullTerminatedList(maxLength: cryptoPwhashStrbytes).toPointer();
    final passwd0 = passwd.toPointer();
    try {
      return _cryptoPwhash.crypto_pwhash_str_verify(
          str0, passwd0, passwd.length);
    } finally {
      calloc.free(passwd0);
      calloc.free(str0);
    }
  }

  static int cryptoPwhashStrNeedsRehash(
      Uint8List str, int opslimit, int memlimit) {
    RangeError.checkValueInInterval(
        str.length, 1, cryptoPwhashStrbytes, 'str', 'Invalid length');
    RangeError.checkValueInInterval(
        opslimit, cryptoPwhashOpslimitMin, cryptoPwhashOpslimitMax, 'opslimit');
    RangeError.checkValueInInterval(
        memlimit, cryptoPwhashMemlimitMin, cryptoPwhashMemlimitMax, 'memlimit');

    // make sure str is null terminated
    final str0 =
        str.toNullTerminatedList(maxLength: cryptoPwhashStrbytes).toPointer();
    try {
      return _cryptoPwhash.crypto_pwhash_str_needs_rehash(
          str0, opslimit, memlimit);
    } finally {
      calloc.free(str0);
    }
  }

  //
  // crypto_scalarmult
  //
  static int get cryptoScalarmultBytes =>
      _cryptoScalarmult.crypto_scalarmult_bytes();
  static int get cryptoScalarmultScalarbytes =>
      _cryptoScalarmult.crypto_scalarmult_scalarbytes();
  static int get cryptoScalarmultCurve25519Bytes =>
      _cryptoScalarmult.crypto_scalarmult_curve25519_bytes();
  static String get cryptoScalarmultPrimitive =>
      _cryptoScalarmult.crypto_scalarmult_primitive().toDartString();

  static Uint8List cryptoScalarmultBase(Uint8List n) {
    RangeError.checkValueInInterval(n.length, cryptoScalarmultScalarbytes,
        cryptoScalarmultScalarbytes, 'n', 'Invalid length');

    final q = calloc<Uint8>(cryptoScalarmultBytes);
    final n0 = n.toPointer();
    try {
      _cryptoScalarmult
          .crypto_scalarmult_base(q, n0)
          .mustSucceed('crypto_scalarmult_base');
      return q.toList(cryptoScalarmultBytes);
    } finally {
      calloc.free(q);
      calloc.free(n0);
    }
  }

  static Uint8List cryptoScalarmult(Uint8List n, Uint8List p) {
    RangeError.checkValueInInterval(n.length, cryptoScalarmultScalarbytes,
        cryptoScalarmultScalarbytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(p.length, cryptoScalarmultBytes,
        cryptoScalarmultBytes, 'p', 'Invalid length');

    final q = calloc<Uint8>(cryptoScalarmultBytes);
    final n0 = n.toPointer();
    final p0 = p.toPointer();
    try {
      _cryptoScalarmult
          .crypto_scalarmult(q, n0, p0)
          .mustSucceed('crypto_scalarmult');
      return q.toList(cryptoScalarmultBytes);
    } finally {
      calloc.free(q);
      calloc.free(n0);
      calloc.free(p0);
    }
  }

  //
  // crypto_secretbox
  //
  static int get cryptoSecretboxKeybytes =>
      _cryptoSecretbox.crypto_secretbox_keybytes();
  static int get cryptoSecretboxNoncebytes =>
      _cryptoSecretbox.crypto_secretbox_noncebytes();
  static int get cryptoSecretboxMacbytes =>
      _cryptoSecretbox.crypto_secretbox_macbytes();
  static int get cryptoSecretboxMessagebytesMax =>
      _cryptoSecretbox.crypto_secretbox_messagebytes_max();
  static String get cryptoSecretboxPrimitive =>
      _cryptoSecretbox.crypto_secretbox_primitive().toDartString();

  static Uint8List cryptoSecretboxEasy(Uint8List m, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(n.length, cryptoSecretboxNoncebytes,
        cryptoSecretboxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoSecretboxKeybytes,
        cryptoSecretboxKeybytes, 'k', 'Invalid length');

    final c = calloc<Uint8>(m.length + cryptoSecretboxMacbytes);
    final m0 = m.toPointer();
    final n0 = n.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoSecretbox
          .crypto_secretbox_easy(c, m0, m.length, n0, k0)
          .mustSucceed('crypto_secretbox_easy');
      return c.toList(m.length + cryptoSecretboxMacbytes);
    } finally {
      calloc.free(c);
      calloc.free(m0);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoSecretboxOpenEasy(
      Uint8List c, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(n.length, cryptoSecretboxNoncebytes,
        cryptoSecretboxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoSecretboxKeybytes,
        cryptoSecretboxKeybytes, 'k', 'Invalid length');

    final m = calloc<Uint8>(c.length - cryptoSecretboxMacbytes);
    final c0 = c.toPointer();
    final n0 = n.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoSecretbox
          .crypto_secretbox_open_easy(m, c0, c.length, n0, k0)
          .mustSucceed('crypto_secretbox_open_easy');
      return m.toList(c.length - cryptoSecretboxMacbytes);
    } finally {
      calloc.free(m);
      calloc.free(c0);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static DetachedCipher cryptoSecretboxDetached(
      Uint8List m, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(n.length, cryptoSecretboxNoncebytes,
        cryptoSecretboxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoSecretboxKeybytes,
        cryptoSecretboxKeybytes, 'k', 'Invalid length');

    final c = calloc<Uint8>(m.length);
    final mac = calloc<Uint8>(cryptoSecretboxMacbytes);
    final m0 = m.toPointer();
    final n0 = n.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoSecretbox
          .crypto_secretbox_detached(c, mac, m0, m.length, n0, k0)
          .mustSucceed('crypto_secretbox_detached');
      return DetachedCipher(
          c: c.toList(m.length), mac: mac.toList(cryptoSecretboxMacbytes));
    } finally {
      calloc.free(c);
      calloc.free(mac);
      calloc.free(m0);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoSecretboxOpenDetached(
      Uint8List c, Uint8List mac, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(mac.length, cryptoSecretboxMacbytes,
        cryptoSecretboxMacbytes, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(n.length, cryptoSecretboxNoncebytes,
        cryptoSecretboxNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoSecretboxKeybytes,
        cryptoSecretboxKeybytes, 'k', 'Invalid length');

    final m = calloc<Uint8>(c.length);
    final mac0 = mac.toPointer();
    final c0 = c.toPointer();
    final n0 = n.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoSecretbox
          .crypto_secretbox_open_detached(m, c0, mac0, c.length, n0, k0)
          .mustSucceed('crypto_secretbox_open_detached');
      return m.toList(c.length);
    } finally {
      calloc.free(m);
      calloc.free(mac0);
      calloc.free(c0);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoSecretboxKeygen() {
    final k = calloc<Uint8>(cryptoSecretboxKeybytes);
    try {
      _cryptoSecretbox.crypto_secretbox_keygen(k);
      return k.toList(cryptoSecretboxKeybytes);
    } finally {
      calloc.free(k);
    }
  }

  //
  // crypto_secretstream
  //
  static int get cryptoSecretstreamXchacha20poly1305Abytes =>
      _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_abytes();
  static int get cryptoSecretstreamXchacha20poly1305Headerbytes =>
      _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_headerbytes();
  static int get cryptoSecretstreamXchacha20poly1305Keybytes =>
      _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_keybytes();
  static int get cryptoSecretstreamXchacha20poly1305MessagebytesMax =>
      _cryptoSecretStream
          .crypto_secretstream_xchacha20poly1305_messagebytes_max();
  static int get cryptoSecretstreamXchacha20poly1305TagMessage =>
      _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_tag_message();
  static int get cryptoSecretstreamXchacha20poly1305TagPush =>
      _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_tag_push();
  static int get cryptoSecretstreamXchacha20poly1305TagRekey =>
      _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_tag_rekey();
  static int get cryptoSecretstreamXchacha20poly1305TagFinal =>
      _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_tag_final();
  static int get cryptoSecretstreamXchacha20poly1305Statebytes =>
      _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_statebytes();

  static Uint8List cryptoSecretstreamXchacha20poly1305Keygen() {
    final k = calloc<Uint8>(cryptoSecretstreamXchacha20poly1305Keybytes);
    try {
      _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_keygen(k);
      return k.toList(cryptoSecretstreamXchacha20poly1305Keybytes);
    } finally {
      calloc.free(k);
    }
  }

  static InitPushResult cryptoSecretstreamXchacha20poly1305InitPush(
      Uint8List key) {
    RangeError.checkValueInInterval(
        key.length,
        cryptoSecretstreamXchacha20poly1305Keybytes,
        cryptoSecretstreamXchacha20poly1305Keybytes,
        'key',
        'Invalid length');

    final state = calloc<Uint8>(cryptoSecretstreamXchacha20poly1305Statebytes);
    final header =
        calloc<Uint8>(cryptoSecretstreamXchacha20poly1305Headerbytes);
    final k = key.toPointer();

    try {
      _cryptoSecretStream
          .crypto_secretstream_xchacha20poly1305_init_push(state, header, k)
          .mustSucceed('crypto_secretstream_xchacha20poly1305_init_push');

      return InitPushResult(
          state: state,
          header:
              header.toList(cryptoSecretstreamXchacha20poly1305Headerbytes));
    } finally {
      calloc.free(header);
      calloc.free(k);
    }
  }

  static Uint8List cryptoSecretstreamXchacha20poly1305Push(
      Pointer<Uint8> state, Uint8List m, Uint8List? ad, int tag) {
    final c =
        calloc<Uint8>(m.length + cryptoSecretstreamXchacha20poly1305Abytes);
    final clenP = calloc<Uint64>(1);
    final m0 = m.toPointer();
    final ad0 = ad?.toPointer() ?? nullptr;
    final adlen = ad?.length ?? 0;
    try {
      _cryptoSecretStream
          .crypto_secretstream_xchacha20poly1305_push(
              state, c, clenP, m0, m.length, ad0, adlen, tag)
          .mustSucceed('crypto_secretstream_xchacha20poly1305_push');

      return c.toList(clenP[0]);
    } finally {
      calloc.free(c);
      calloc.free(clenP);
      calloc.free(m0);
      calloc.free(ad0);
    }
  }

  static Pointer<Uint8> cryptoSecretstreamXchacha20poly1305InitPull(
      Uint8List header, Uint8List k) {
    RangeError.checkValueInInterval(
        header.length,
        cryptoSecretstreamXchacha20poly1305Headerbytes,
        cryptoSecretstreamXchacha20poly1305Headerbytes,
        'header',
        'Invalid length');
    RangeError.checkValueInInterval(
        k.length,
        cryptoSecretstreamXchacha20poly1305Keybytes,
        cryptoSecretstreamXchacha20poly1305Keybytes,
        'k',
        'Invalid length');

    final state = calloc<Uint8>(cryptoSecretstreamXchacha20poly1305Statebytes);
    final header0 = header.toPointer();
    final k0 = k.toPointer();

    try {
      _cryptoSecretStream
          .crypto_secretstream_xchacha20poly1305_init_pull(state, header0, k0)
          .mustSucceed('crypto_secretstream_xchacha20poly1305_init_pull');
      return state;
    } finally {
      calloc.free(header0);
      calloc.free(k0);
    }
  }

  static PullResult cryptoSecretstreamXchacha20poly1305Pull(
      Pointer<Uint8> state, Uint8List c, Uint8List? ad) {
    final m =
        calloc<Uint8>(c.length - cryptoSecretstreamXchacha20poly1305Abytes);
    final mlenP = calloc<Uint64>(1);
    final tagP = calloc<Uint8>(1);
    final c0 = c.toPointer();
    final ad0 = ad?.toPointer() ?? nullptr;
    final adlen = ad?.length ?? 0;
    try {
      _cryptoSecretStream
          .crypto_secretstream_xchacha20poly1305_pull(
            state,
            m,
            mlenP,
            tagP,
            c0,
            c.length,
            ad0,
            adlen,
          )
          .mustSucceed('crypto_secretstream_xchacha20poly1305_pull');

      return PullResult(m: m.toList(mlenP[0]), tag: tagP[0]);
    } finally {
      calloc.free(m);
      calloc.free(mlenP);
      calloc.free(tagP);
      calloc.free(c0);
      calloc.free(ad0);
    }
  }

  static void cryptoSecretstreamXchacha20poly1305Rekey(Pointer<Uint8> state) {
    _cryptoSecretStream.crypto_secretstream_xchacha20poly1305_rekey(state);
  }

  //
  // crypto_shorthash
  //
  static int get cryptoShorthashBytes =>
      _cryptoShorthash.crypto_shorthash_bytes();
  static int get cryptoShorthashKeybytes =>
      _cryptoShorthash.crypto_shorthash_keybytes();
  static String get cryptoShorthashPrimitive =>
      _cryptoShorthash.crypto_shorthash_primitive().toDartString();

  static Uint8List cryptoShorthash(Uint8List i, Uint8List k) {
    RangeError.checkValueInInterval(k.length, cryptoShorthashKeybytes,
        cryptoShorthashKeybytes, 'k', 'Invalid length');

    final out = calloc<Uint8>(cryptoShorthashBytes);
    final i0 = i.toPointer();
    final k0 = k.toPointer();
    try {
      _cryptoShorthash
          .crypto_shorthash(out, i0, i.length, k0)
          .mustSucceed('crypto_shorthash');
      return out.toList(cryptoShorthashBytes);
    } finally {
      calloc.free(out);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoShorthashKeygen() {
    final k = calloc<Uint8>(cryptoShorthashKeybytes);
    try {
      _cryptoShorthash.crypto_shorthash_keygen(k);
      return k.toList(cryptoShorthashKeybytes);
    } finally {
      calloc.free(k);
    }
  }

  //
  // crypto_sign
  //
  static int get cryptoSignStatebytes => _cryptoSign.crypto_sign_statebytes();
  static int get cryptoSignBytes => _cryptoSign.crypto_sign_bytes();
  static int get cryptoSignSeedbytes => _cryptoSign.crypto_sign_seedbytes();
  static int get cryptoSignPublickeybytes =>
      _cryptoSign.crypto_sign_publickeybytes();
  static int get cryptoSignSecretkeybytes =>
      _cryptoSign.crypto_sign_secretkeybytes();
  static int get cryptoSignMessagebytesMax =>
      _cryptoSign.crypto_sign_messagebytes_max();
  static int get cryptoSignEd25519Publickeybytes =>
      _cryptoSign.crypto_sign_ed25519_publickeybytes();
  static int get cryptoSignEd25519Secretkeybytes =>
      _cryptoSign.crypto_sign_ed25519_secretkeybytes();
  static String get cryptoSignPrimitive =>
      _cryptoSign.crypto_sign_primitive().toDartString();

  static KeyPair cryptoSignSeedKeypair(Uint8List seed) {
    RangeError.checkValueInInterval(seed.length, cryptoSignSeedbytes,
        cryptoSignSeedbytes, 'seed', 'Invalid length');
    final pk = calloc<Uint8>(cryptoSignPublickeybytes);
    final sk = calloc<Uint8>(cryptoSignSecretkeybytes);
    final seed0 = seed.toPointer();

    try {
      _cryptoSign
          .crypto_sign_seed_keypair(pk, sk, seed0)
          .mustSucceed('crypto_sign_seed_keypair');
      return KeyPair(
          pk: pk.toList(cryptoSignPublickeybytes),
          sk: sk.toList(cryptoSignSecretkeybytes));
    } finally {
      calloc.free(pk);
      calloc.free(sk);
      calloc.free(seed0);
    }
  }

  static KeyPair cryptoSignKeypair() {
    final pk = calloc<Uint8>(cryptoSignPublickeybytes);
    final sk = calloc<Uint8>(cryptoSignSecretkeybytes);

    try {
      _cryptoSign
          .crypto_sign_keypair(pk, sk)
          .mustSucceed('crypto_sign_keypair');
      return KeyPair(
          pk: pk.toList(cryptoSignPublickeybytes),
          sk: sk.toList(cryptoSignSecretkeybytes));
    } finally {
      calloc.free(pk);
      calloc.free(sk);
    }
  }

  static Uint8List cryptoSign(Uint8List m, Uint8List sk) {
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final sm = calloc<Uint8>(m.length + cryptoSignBytes);
    final smlenP = calloc<Uint64>(1);
    final m0 = m.toPointer();
    final sk0 = sk.toPointer();

    try {
      _cryptoSign
          .crypto_sign(sm, smlenP, m0, m.length, sk0)
          .mustSucceed('crypto_sign');
      return sm.toList(smlenP[0]);
    } finally {
      calloc.free(sm);
      calloc.free(smlenP);
      calloc.free(m0);
      calloc.free(sk0);
    }
  }

  static Uint8List cryptoSignOpen(Uint8List sm, Uint8List pk) {
    RangeError.checkValueInInterval(pk.length, cryptoSignPublickeybytes,
        cryptoSignPublickeybytes, 'pk', 'Invalid length');

    final m = calloc<Uint8>(sm.length - cryptoSignBytes);
    final mlenP = calloc<Uint64>(1);
    final sm0 = sm.toPointer();
    final pk0 = pk.toPointer();

    try {
      _cryptoSign
          .crypto_sign_open(m, mlenP, sm0, sm.length, pk0)
          .mustSucceed('crypto_sign_open');
      return m.toList(mlenP[0]);
    } finally {
      calloc.free(m);
      calloc.free(mlenP);
      calloc.free(sm0);
      calloc.free(pk0);
    }
  }

  static Uint8List cryptoSignDetached(Uint8List m, Uint8List sk) {
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final sig = calloc<Uint8>(cryptoSignBytes);
    final siglenP = calloc<Uint64>(1);
    final m0 = m.toPointer();
    final sk0 = sk.toPointer();

    try {
      _cryptoSign
          .crypto_sign_detached(sig, siglenP, m0, m.length, sk0)
          .mustSucceed('crypto_sign_detached');
      return sig.toList(siglenP[0]);
    } finally {
      calloc.free(sig);
      calloc.free(siglenP);
      calloc.free(m0);
      calloc.free(sk0);
    }
  }

  static int cryptoSignVerifyDetached(
      Uint8List sig, Uint8List m, Uint8List pk) {
    RangeError.checkValueInInterval(
        sig.length, cryptoSignBytes, cryptoSignBytes, 'sig', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoSignPublickeybytes,
        cryptoSignPublickeybytes, 'pk', 'Invalid length');

    final sig0 = sig.toPointer();
    final m0 = m.toPointer();
    final pk0 = pk.toPointer();

    try {
      return _cryptoSign.crypto_sign_verify_detached(sig0, m0, m.length, pk0);
    } finally {
      calloc.free(sig0);
      calloc.free(m0);
      calloc.free(pk0);
    }
  }

  static Pointer<Uint8> cryptoSignInit() {
    final state = calloc<Uint8>(cryptoSignStatebytes);
    _cryptoSign.crypto_sign_init(state).mustSucceed('crypto_sign_init');
    return state;
  }

  static void cryptoSignUpdate(Pointer<Uint8> state, Uint8List m) {
    final m0 = m.toPointer();
    try {
      _cryptoSign
          .crypto_sign_update(state, m0, m.length)
          .mustSucceed('crypto_sign_update');
    } finally {
      calloc.free(m0);
    }
  }

  static Uint8List cryptoSignFinalCreate(Pointer<Uint8> state, Uint8List sk) {
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final sig = calloc<Uint8>(cryptoSignBytes);
    final siglenP = calloc<Uint64>(1);
    final sk0 = sk.toPointer();
    try {
      _cryptoSign
          .crypto_sign_final_create(state, sig, siglenP, sk0)
          .mustSucceed('crypto_sign_final_create');
      return sig.toList(siglenP[0]);
    } finally {
      // note: caller is responsible for freeing state
      calloc.free(sig);
      calloc.free(siglenP);
      calloc.free(sk0);
    }
  }

  static int cryptoSignFinalVerify(
      Pointer<Uint8> state, Uint8List sig, Uint8List pk) {
    RangeError.checkValueInInterval(
        sig.length, cryptoSignBytes, cryptoSignBytes, 'sig', 'Invalid length');
    RangeError.checkValueInInterval(pk.length, cryptoSignPublickeybytes,
        cryptoSignPublickeybytes, 'pk', 'Invalid length');

    final sig0 = sig.toPointer();
    final pk0 = pk.toPointer();
    try {
      return _cryptoSign.crypto_sign_final_verify(state, sig0, pk0);
    } finally {
      // note: caller is responsible for freeing state
      calloc.free(sig0);
      calloc.free(pk0);
    }
  }

  static Uint8List cryptoSignEd25519SkToSeed(Uint8List sk) {
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final seed = calloc<Uint8>(cryptoSignSeedbytes);
    final sk0 = sk.toPointer();
    try {
      _cryptoSign
          .crypto_sign_ed25519_sk_to_seed(seed, sk0)
          .mustSucceed('crypto_sign_ed25519_sk_to_seed');
      return seed.toList(cryptoSignSeedbytes);
    } finally {
      calloc.free(seed);
      calloc.free(sk0);
    }
  }

  static Uint8List cryptoSignEd25519SkToPk(Uint8List sk) {
    RangeError.checkValueInInterval(sk.length, cryptoSignSecretkeybytes,
        cryptoSignSecretkeybytes, 'sk', 'Invalid length');

    final pk = calloc<Uint8>(cryptoSignPublickeybytes);
    final sk0 = sk.toPointer();
    try {
      _cryptoSign
          .crypto_sign_ed25519_sk_to_pk(pk, sk0)
          .mustSucceed('crypto_sign_ed25519_sk_to_pk');
      return pk.toList(cryptoSignPublickeybytes);
    } finally {
      calloc.free(pk);
      calloc.free(sk0);
    }
  }

  static Uint8List cryptoSignEd25519PkToCurve25519(Uint8List ed25519Pk) {
    RangeError.checkValueInInterval(
        ed25519Pk.length,
        cryptoSignEd25519Publickeybytes,
        cryptoSignEd25519Publickeybytes,
        'ed25519Pk',
        'Invalid length');

    final curve25519Pk = calloc<Uint8>(cryptoScalarmultCurve25519Bytes);
    final ed25519Pk0 = ed25519Pk.toPointer();
    try {
      _cryptoSign
          .crypto_sign_ed25519_pk_to_curve25519(curve25519Pk, ed25519Pk0)
          .mustSucceed('crypto_sign_ed25519_pk_to_curve25519');
      return curve25519Pk.toList(cryptoScalarmultCurve25519Bytes);
    } finally {
      calloc.free(curve25519Pk);
      calloc.free(ed25519Pk0);
    }
  }

  static Uint8List cryptoSignEd25519SkToCurve25519(Uint8List ed25519Sk) {
    RangeError.checkValueInInterval(
        ed25519Sk.length,
        cryptoSignEd25519Secretkeybytes,
        cryptoSignEd25519Secretkeybytes,
        'ed25519Sk',
        'Invalid length');

    final curve25519Pk = calloc<Uint8>(cryptoScalarmultCurve25519Bytes);
    final ed25519Sk0 = ed25519Sk.toPointer();
    try {
      _cryptoSign
          .crypto_sign_ed25519_sk_to_curve25519(curve25519Pk, ed25519Sk0)
          .mustSucceed('crypto_sign_ed25519_sk_to_curve25519');
      return curve25519Pk.toList(cryptoScalarmultCurve25519Bytes);
    } finally {
      calloc.free(curve25519Pk);
      calloc.free(ed25519Sk0);
    }
  }

  //
  // crypto_stream
  //
  static int get cryptoStreamKeybytes => _cryptoStream.crypto_stream_keybytes();
  static int get cryptoStreamNoncebytes =>
      _cryptoStream.crypto_stream_noncebytes();
  static int get cryptoStreamMessagebytesMax =>
      _cryptoStream.crypto_stream_messagebytes_max();
  static String get cryptoStreamPrimitive =>
      _cryptoStream.crypto_stream_primitive().toDartString();

  static Uint8List cryptoStream(int clen, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(n.length, cryptoStreamNoncebytes,
        cryptoStreamNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoStreamKeybytes,
        cryptoStreamKeybytes, 'k', 'Invalid length');

    final c = calloc<Uint8>(clen);
    final n0 = n.toPointer();
    final k0 = k.toPointer();
    try {
      _cryptoStream.crypto_stream(c, clen, n0, k0).mustSucceed('crypto_stream');
      return c.toList(clen);
    } finally {
      calloc.free(c);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoStreamXor(Uint8List m, Uint8List n, Uint8List k) {
    RangeError.checkValueInInterval(n.length, cryptoStreamNoncebytes,
        cryptoStreamNoncebytes, 'n', 'Invalid length');
    RangeError.checkValueInInterval(k.length, cryptoStreamKeybytes,
        cryptoStreamKeybytes, 'k', 'Invalid length');

    final c = calloc<Uint8>(m.length);
    final m0 = m.toPointer();
    final n0 = n.toPointer();
    final k0 = k.toPointer();
    try {
      _cryptoStream
          .crypto_stream_xor(c, m0, m.length, n0, k0)
          .mustSucceed('crypto_stream_xor');
      return c.toList(m.length);
    } finally {
      calloc.free(c);
      calloc.free(m0);
      calloc.free(n0);
      calloc.free(k0);
    }
  }

  static Uint8List cryptoStreamKeygen() {
    final k = calloc<Uint8>(cryptoStreamKeybytes);
    try {
      _cryptoStream.crypto_stream_keygen(k);
      return k.toList(cryptoStreamKeybytes);
    } finally {
      calloc.free(k);
    }
  }

  //
  // randombytes
  //
  static int get randombytesSeedbytes => _randombytes.randombytes_seedbytes();

  static Uint8List randombytesBuf(int size) {
    RangeError.checkNotNegative(size);

    final buf = calloc<Uint8>(size);
    try {
      _randombytes.randombytes_buf(buf, size);
      return buf.toList(size);
    } finally {
      calloc.free(buf);
    }
  }

  static Uint8List randombytesBufDeterministic(int size, Uint8List seed) {
    RangeError.checkNotNegative(size);
    RangeError.checkValueInInterval(seed.length, randombytesSeedbytes,
        randombytesSeedbytes, 'seed', 'Invalid length');

    final buf = calloc<Uint8>(size);
    final seed0 = seed.toPointer();
    try {
      _randombytes.randombytes_buf_deterministic(buf, size, seed0);
      return buf.toList(size);
    } finally {
      calloc.free(buf);
      calloc.free(seed0);
    }
  }

  static int randombytesRandom() => _randombytes.randombytes_random();

  static int randombytesUniform(int upperBound) {
    RangeError.checkNotNegative(upperBound);

    return _randombytes.randombytes_uniform(upperBound);
  }

  static void randombytesStir() => _randombytes.randombytes_stir();
  static void randombytesClose() => _randombytes.randombytes_close();

  static String get randombytesImplementationName =>
      _randombytes.randombytes_implementation_name().toDartString();

  //
  // sodium
  //
  static void init() {
    if (_sodium.sodium_init() == -1) {
      throw SodiumException('Libsodium initialization failed');
    }
  }

  static String get versionString =>
      _sodium.sodium_version_string().toDartString();
  static int get libraryVersionMajor => _sodium.sodium_library_version_major();
  static int get libraryVersionMinor => _sodium.sodium_library_version_minor();
  static bool get libraryMinimal => _sodium.sodium_library_minimal() == 1;

  static bool get runtimeHasNeon => _sodium.sodium_runtime_has_neon() == 1;
  static bool get runtimeHasSse2 => _sodium.sodium_runtime_has_sse2() == 1;
  static bool get runtimeHasSse3 => _sodium.sodium_runtime_has_sse3() == 1;
  static bool get runtimeHasSsse3 => _sodium.sodium_runtime_has_ssse3() == 1;
  static bool get runtimeHasSse41 => _sodium.sodium_runtime_has_sse41() == 1;
  static bool get runtimeHasAvx => _sodium.sodium_runtime_has_avx() == 1;
  static bool get runtimeHasAvx2 => _sodium.sodium_runtime_has_avx2() == 1;
  static bool get runtimeHasAvx512f =>
      _sodium.sodium_runtime_has_avx512f() == 1;
  static bool get runtimeHasPclmul => _sodium.sodium_runtime_has_pclmul() == 1;
  static bool get runtimeHasAesni => _sodium.sodium_runtime_has_aesni() == 1;
  static bool get runtimeHasRdrand => _sodium.sodium_runtime_has_rdrand() == 1;

  static String bin2hex(Uint8List bin) {
    final hexMaxlen = bin.length * 2 + 1;
    final hex = calloc<Uint8>(hexMaxlen);
    final bin0 = bin.toPointer();
    try {
      return _sodium
          .sodium_bin2hex(hex, hexMaxlen, bin0, bin.length)
          .toDartString();
    } finally {
      calloc.free(hex);
      calloc.free(bin0);
    }
  }

  static Uint8List hex2bin(String hex, {String? ignore = ': '}) {
    final bin = calloc<Uint8>(hex.length);
    final hex0 = hex.toNativeUtf8();
    final ignore0 = ignore == null ? nullptr : ignore.toNativeUtf8();
    final binlen0 = calloc<Uint8>(4);
    try {
      _sodium
          .sodium_hex2bin(
              bin, hex.length, hex0, hex0.length, ignore0, binlen0, nullptr)
          .mustSucceed('sodium_hex2bin');

      final binlen =
          binlen0.toList(4).buffer.asByteData().getUint32(0, Endian.host);
      return bin.toList(binlen);
    } finally {
      calloc.free(bin);
      calloc.free(hex0);
      calloc.free(ignore0);
      calloc.free(binlen0);
    }
  }

  static const int base64VariantOriginal = 1;
  static const int base64VariantOriginalNoPadding = 3;
  static const int base64VariantUrlsafe = 5;
  static const int base64VariantUrlsafeNoPadding = 7;

  static int base64EncodedLen(int binlen, int variant) =>
      _sodium.sodium_base64_encoded_len(binlen, variant);

  static String bin2base64(Uint8List bin,
      {int variant = base64VariantOriginal}) {
    final b64maxlen = _sodium.sodium_base64_encoded_len(bin.length, variant);
    final b64 = calloc<Uint8>(b64maxlen);
    final bin0 = bin.toPointer();
    try {
      return _sodium
          .sodium_bin2base64(b64, b64maxlen, bin0, bin.length, variant)
          .toDartString();
    } finally {
      calloc.free(b64);
      calloc.free(bin0);
    }
  }

  static Uint8List base642bin(String b64,
      {String? ignore, int variant = base64VariantOriginal}) {
    final bin = calloc<Uint8>(b64.length);
    final b640 = b64.toNativeUtf8();
    final ignore0 = ignore == null ? nullptr : ignore.toNativeUtf8();
    final binlen0 = calloc<Uint8>(4);
    try {
      _sodium
          .sodium_base642bin(bin, b64.length, b640, b640.length, ignore0,
              binlen0, nullptr, variant)
          .mustSucceed('sodium_base642bin');

      final binlen =
          binlen0.toList(4).buffer.asByteData().getUint32(0, Endian.host);
      return bin.toList(binlen);
    } finally {
      calloc.free(bin);
      calloc.free(b640);
      calloc.free(ignore0);
      calloc.free(binlen0);
    }
  }

  static bool memcmp(Uint8List b1, Uint8List b2) {
    if (b1.length != b2.length) {
      return false;
    }
    final b10 = b1.toPointer();
    final b20 = b2.toPointer();
    try {
      return _sodium.sodium_memcmp(b10, b20, b1.length) == 0;
    } finally {
      calloc.free(b10);
      calloc.free(b20);
    }
  }

  static Uint8List pad(Uint8List buf, int blockSize) {
    final buf0 = buf.toPointer(size: buf.length + blockSize);
    final paddedlen = calloc<Uint32>(1);
    try {
      _sodium
          .sodium_pad(
              paddedlen, buf0, buf.length, blockSize, buf.length + blockSize)
          .mustSucceed('sodium_pad');

      return buf0.toList(paddedlen[0]);
    } finally {
      calloc.free(buf0);
      calloc.free(paddedlen);
    }
  }

  static Uint8List unpad(Uint8List buf, int blockSize) {
    final buf0 = buf.toPointer();
    final unpaddedlen = calloc<Uint32>(1);
    try {
      _sodium
          .sodium_unpad(unpaddedlen, buf0, buf.length, blockSize)
          .mustSucceed('sodium_unpad');

      return buf0.toList(unpaddedlen[0]);
    } finally {
      calloc.free(buf0);
      calloc.free(unpaddedlen);
    }
  }
}

class _CryptoAead {
  final String name;
  final CryptoAeadBindings _bindings;
  _CryptoAead(this.name) : _bindings = CryptoAeadBindings(name);
  _CryptoAead.chacha20poly1305() : this('crypto_aead_chacha20poly1305');
  _CryptoAead.chacha20poly1305Ietf()
      : this('crypto_aead_chacha20poly1305_ietf');
  _CryptoAead.xchacha20poly1305Ietf()
      : this('crypto_aead_xchacha20poly1305_ietf');

  int get keybytes => _bindings.keybytes();
  int get nsecbytes => _bindings.nsecbytes();
  int get npubbytes => _bindings.npubbytes();
  int get abytes => _bindings.abytes();
  int get messagebytesMax => _bindings.messagebytes_max();

  Uint8List encrypt(Uint8List m, Uint8List? ad, Uint8List? nsec, Uint8List npub,
      Uint8List k) {
    assert(nsec == null); // yes, nsec must be null

    RangeError.checkValueInInterval(
        npub.length, npubbytes, npubbytes, 'npub', 'Invalid length');
    RangeError.checkValueInInterval(
        k.length, keybytes, keybytes, 'k', 'Invalid length');

    final c = calloc<Uint8>(m.length + abytes);
    final clenP = calloc<Uint64>(1);
    final m0 = m.toPointer();
    final ad0 = ad?.toPointer() ?? nullptr;
    final adlen = ad?.length ?? 0;
    final npub0 = npub.toPointer();
    final k0 = k.toPointer();
    try {
      _bindings
          .encrypt(c, clenP, m0, m.length, ad0, adlen, nullptr, npub0, k0)
          .mustSucceed('${name}_encrypt');
      return c.toList(clenP[0]);
    } finally {
      calloc.free(c);
      calloc.free(clenP);
      calloc.free(m0);
      calloc.free(ad0);
      calloc.free(npub0);
      calloc.free(k0);
    }
  }

  Uint8List decrypt(Uint8List? nsec, Uint8List c, Uint8List? ad, Uint8List npub,
      Uint8List k) {
    assert(nsec == null); // yes, nsec must be null
    RangeError.checkValueInInterval(
        npub.length, npubbytes, npubbytes, 'npub', 'Invalid length');
    RangeError.checkValueInInterval(
        k.length, keybytes, keybytes, 'k', 'Invalid length');

    final m = calloc<Uint8>(c.length - abytes);
    final mlenP = calloc<Uint64>(1);
    final c0 = c.toPointer();
    final ad0 = ad?.toPointer() ?? nullptr;
    final adlen = ad?.length ?? 0;
    final npub0 = npub.toPointer();
    final k0 = k.toPointer();
    try {
      _bindings
          .decrypt(m, mlenP, nullptr, c0, c.length, ad0, adlen, npub0, k0)
          .mustSucceed('${name}_decrypt');
      return m.toList(mlenP[0]);
    } finally {
      calloc.free(m);
      calloc.free(mlenP);
      calloc.free(c0);
      calloc.free(ad0);
      calloc.free(npub0);
      calloc.free(k0);
    }
  }

  DetachedCipher encryptDetached(Uint8List m, Uint8List? ad, Uint8List? nsec,
      Uint8List npub, Uint8List k) {
    assert(nsec == null); // yes, nsec must be null
    RangeError.checkValueInInterval(
        npub.length, npubbytes, npubbytes, 'npub', 'Invalid length');
    RangeError.checkValueInInterval(
        k.length, keybytes, keybytes, 'k', 'Invalid length');

    final c = calloc<Uint8>(m.length);
    final mac = calloc<Uint8>(abytes);
    final maclenP = calloc<Uint64>(1);
    final m0 = m.toPointer();
    final ad0 = ad?.toPointer() ?? nullptr;
    final adlen = ad?.length ?? 0;
    final npub0 = npub.toPointer();
    final k0 = k.toPointer();
    try {
      _bindings
          .encrypt_detached(
              c, mac, maclenP, m0, m.length, ad0, adlen, nullptr, npub0, k0)
          .mustSucceed('${name}_encrypt_detached');
      return DetachedCipher(c: c.toList(m.length), mac: mac.toList(maclenP[0]));
    } finally {
      calloc.free(c);
      calloc.free(mac);
      calloc.free(maclenP);
      calloc.free(m0);
      calloc.free(ad0);
      calloc.free(npub0);
      calloc.free(k0);
    }
  }

  Uint8List decryptDetached(Uint8List? nsec, Uint8List c, Uint8List mac,
      Uint8List? ad, Uint8List npub, Uint8List k) {
    assert(nsec == null); // yes, nsec must be null
    RangeError.checkValueInInterval(
        mac.length, abytes, abytes, 'mac', 'Invalid length');
    RangeError.checkValueInInterval(
        npub.length, npubbytes, npubbytes, 'npub', 'Invalid length');
    RangeError.checkValueInInterval(
        k.length, keybytes, keybytes, 'k', 'Invalid length');

    final m = calloc<Uint8>(c.length);
    final c0 = c.toPointer();
    final mac0 = mac.toPointer();
    final ad0 = ad?.toPointer() ?? nullptr;
    final adlen = ad?.length ?? 0;
    final npub0 = npub.toPointer();
    final k0 = k.toPointer();
    try {
      _bindings
          .decrypt_detached(
              m, nullptr, c0, c.length, mac0, ad0, adlen, npub0, k0)
          .mustSucceed('${name}_decrypt_detached');
      return m.toList(c.length);
    } finally {
      calloc.free(m);
      calloc.free(c0);
      calloc.free(mac0);
      calloc.free(ad0);
      calloc.free(npub0);
      calloc.free(k0);
    }
  }

  Uint8List keygen() {
    final k = calloc<Uint8>(keybytes);
    try {
      _bindings.keygen(k);
      return k.toList(keybytes);
    } finally {
      calloc.free(k);
    }
  }
}
