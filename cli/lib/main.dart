import 'dart:io';

import 'package:args/args.dart';
import 'package:path/path.dart' as path;

import 'package:crypto/crypto.dart';
import 'package:webcrypto/webcrypto.dart';
import 'dart:convert'; // for the utf8.encode method
import 'dart:typed_data';
// import 'package:cryptography/cryptography.dart'; // これはcryptoとの相性が悪い

Future<void> main(List<String> arguments) async {
  final parser = ArgParser();

  parser.addFlag('help', abbr: 'h', negatable: false, help: 'Prints usage information', defaultsTo: false);
  parser.addFlag('receive', abbr: 'r', negatable: false, help: 'Start a server to receive files', defaultsTo: false);
  parser.addFlag('send', abbr: 's', negatable: false, help: 'Setups a client to send files', defaultsTo: false);

  final results = parser.parse(arguments);

  if (results['help']) {
    _printUsage(parser);
    return;
  }

  final receive = results['receive'] as bool;
  final send = results['send'] as bool;

  // DH鍵共有 key
  // Fundamental Elliptic Curve Cryptography Algorithms (RFC6090, Feb. 2011)
  // Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> generateKey(EllipticCurve curve)
  var aliceKeyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
  var alicePrivateKey = aliceKeyPair.privateKey;
  var alicePublicKey = aliceKeyPair.publicKey;
  print(aliceKeyPair);
  print(alicePrivateKey);
  print(alicePublicKey);
  var rawAlicePrivateKey = await alicePrivateKey.exportPkcs8Key();
  var rawAlicePublicKey = await alicePublicKey.exportRawKey();
  print("rawAlicePrivateKey: $rawAlicePrivateKey");
  print("rawAlicePublicKey: $rawAlicePublicKey");

  var bobKeyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
  var bobPrivateKey = bobKeyPair.privateKey;
  var bobPublicKey = bobKeyPair.publicKey;
  var rawBobPrivateKey = await bobPrivateKey.exportPkcs8Key();
  var rawBobPublicKey = await bobPublicKey.exportRawKey();
  print("rawBobPrivateKey: ${rawBobPrivateKey.length} $rawBobPrivateKey");
  print("rawBobPublicKey: ${rawBobPublicKey.length} $rawBobPublicKey");

  var aliceBits = await alicePrivateKey.deriveBits(256, bobPublicKey);
  var bobBits = await bobPrivateKey.deriveBits(256, alicePublicKey);
  print("aliceBits: ${aliceBits.length} $aliceBits");
  print("bobBits  : ${bobBits.length} $bobBits");

  var key = utf8.encode("foobar"); // key of HOTP
  var counter = 0x0123456789abcdef; // counter of HOTP; Dart int: 8 bytes

  // HOTP, RFC 4226, Dec. 2005.
  var digest = _hotp_hmac_sha_1(key, counter);
  int code = _hotp_truncate(digest);
  
  if (receive) {
    print('Starting server...');
  } else if (send) {
    print('Setting up client...');
  } else {
    _printUsage(parser);
  }
}

// Sec. 5.3 of HOTP, RFC 4226, Dec. 2005.
// HMAC, RFC 2104, Feb. 1997.
Digest _hotp_hmac_sha_1(key, int counter) {
  print("counter: ${counter.toRadixString(16)}");

  var bytes = Uint8List(8); // Converter<int, Uint8List>
  for (int i = 0; i < 8; i++) {
    bytes[7 - i] = (counter >> (8 * i)) & 0xff;
  }
  print("counter as bytes: ${bytes.map((i) => i.toRadixString(16))}");

  final hmacSha1 = Hmac(sha1, key);
  final digest = hmacSha1.convert(bytes);
  print("Digest as byte length: ${digest.bytes.length}");
  print("Digest as bytes: ${digest.bytes.map((i) => i.toRadixString(16))}");
  print("Digest as hex string: $digest");
  return digest;
}

// Sec. 5.4 of HOTP, RFC 4226, Dec. 2005.
int _hotp_truncate(Digest digest) {
  final int offset = digest.bytes[19] & 0xf ;
  print("HOTP offset: $offset");

  int bin_code = (digest.bytes[offset]  & 0x7f) << 24
           | (digest.bytes[offset+1] & 0xff) << 16
           | (digest.bytes[offset+2] & 0xff) <<  8
           | (digest.bytes[offset+3] & 0xff);
  print("HOTP bin_code: $bin_code");
  bin_code %= 1000000; // truncate
  print("HOTP 6-digit bin_code: $bin_code");
  return bin_code;
}

void _printUsage(ArgParser parser) {
  print('The LocalSend CLI to send and receive files locally.');
  print('');
  print('Usage: ${path.basename(Platform.executable)} [options]');
  print('');
  print('Options:');
  print(parser.usage);
}
