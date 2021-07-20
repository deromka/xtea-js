var ROUNDS = 32;
var DELTA = 0x9E3779B9;

/** @private */
function encipher( v, k ) {
  var y = v[0];
  var z = v[1];
  var sum = 0;
  var limit = (DELTA * ROUNDS) >>> 0;

  while ( sum !== limit ) {
    y += (((z << 4) >>> 0 ^ (z >>> 5)) + z) ^ (sum + k[sum & 3]);
    y = y >>> 0;
    sum = (sum + DELTA) >>> 0;
    z += (((y << 4) >>> 0 ^ (y >>> 5)) + y) ^ (sum + k[(sum >> 11) & 3]);
    z = z >>> 0;
  }
  v[0] = y;
  v[1] = z;
}

/** @private */
function decipher( v, k ) {
  var y = v[0];
  var z = v[1];
  var sum = (DELTA * ROUNDS) >>> 0;

  while (sum) {
    z -= (((y << 4) >>> 0 ^ (y >>> 5)) + y) ^ (sum + k[(sum >> 11) & 3]);
    z = z >>> 0;
    sum = (sum - DELTA) >>> 0;
    y -= (((z << 4) >>> 0 ^ (z >>> 5)) + z) ^ (sum + k[sum & 3]);
    y = y >>> 0;
  }
  v[0] = y;
  v[1] = z;
}

/** @private */
function encipher_cbc( v, k, iv ) {
  v[0] ^= iv[0];
  v[1] ^= iv[1];
  encipher( v, k );
  iv[0] = v[0];
  iv[1] = v[1];
}

/** @private */
function decipher_cbc( v, k, iv ) {
  var tmp = new Uint32Array(v);
  decipher( v, k );
  v[0] ^= iv[0];
  v[1] ^= iv[1];
  iv[0] = tmp[0];
  iv[1] = tmp[1];
}

function uint32_to_uint8_big_endian( num ) {
  const out = new Uint8Array(4);

  // big endian
  out[3] = 0xFF & num
  out[2] = 0xFF & (num >> 8)
  out[1] = 0xFF & (num >> 16)
  out[0] = 0xFF & (num >> 24)

  return out
}

function uint8_arr_to_uint32_big_endian( arr ) {
  const dv = new DataView(arr);
  return dv.getUint32(0, false)
}

function concat_arrays( a, b ) {
  const out = new Uint8Array( a.length + b.length )
  out.set(a)
  out.set(b, a.length)

  return out
}

/** @private */
function doBlock( method, block ,key ) {
  var k = new Uint32Array(4);
  var v = new Uint32Array(2);
  var out = new Uint8Array(8);

  for (var i = 0; i < 4; ++i) {
    //k[i] = key.readUInt32BE(i * 4);
    k[i] = uint8_arr_to_uint32_big_endian(key.buffer.slice(i*4, (i*4)+4))
  }
  //v[0] = block.readUInt32BE(0);
  //v[1] = block.readUInt32BE(4);
  v[0] = uint8_arr_to_uint32_big_endian(block.buffer.slice(0, 4))
  v[1] = uint8_arr_to_uint32_big_endian(block.buffer.slice(4, 8))

  method( v, k );

  //out.writeUInt32BE(v[0], 0);
  //out.writeUInt32BE(v[1], 4);

  out.set(uint32_to_uint8_big_endian(v[0]), 0)
  out.set(uint32_to_uint8_big_endian(v[1]), 4)

  return out
}

var MODES = {
  ecb: { encrypt: encipher, decrypt: decipher },
  cbc: { encrypt: encipher_cbc, decrypt: decipher_cbc }
}

/** @private */
function doBlocks( encryption, msg, key, mode, ivbuf, skippad ) {
  mode = mode || 'ecb';
  if (!ivbuf) {
    ivbuf = new Uint8Array(8);
    ivbuf.fill(0);
  }

  var mode_ = MODES[ mode ];
  if (!mode_) {
    throw new Error('Unimplemented mode: ' + mode);
  }

  var method;
  if (encryption) {
    method = mode_.encrypt;
  } else {
    method = mode_.decrypt;
  }

  var length = msg.length;
  var pad = 8 - (length & 7);

  if ( skippad || ! encryption ) {
    if (pad !== 8) {
      throw new Error("Data not aligned to 8 bytes block boundary");
    }
    pad = 0;
  }

  var out = new Uint8Array(length + pad);
  var k = new Uint32Array(4);
  var v = new Uint32Array(2);
  var iv = new Uint32Array(2);

  //iv[0] = ivbuf.readUInt32BE(0);
  //iv[1] = ivbuf.readUInt32BE(4);
  iv[0] = uint8_arr_to_uint32_big_endian(ivbuf.buffer.slice(0, 4))
  iv[1] = uint8_arr_to_uint32_big_endian(ivbuf.buffer.slice(4, 8))

  for (var i = 0; i < 4; ++i) {
    //k[i] = key.readUInt32BE(i * 4);
    k[i] = uint8_arr_to_uint32_big_endian(key.buffer.slice(i*4, (i*4)+4))
  }

  var offset = 0;
  while (offset <= length) {
    if (length - offset < 8) {
      if ( skippad || ! encryption ) {
        break;
      }

      var buf = new Uint8Array( pad );
      buf.fill( pad );

      buf = concat_arrays(msg.slice( offset ), buf );
      v[0] = uint8_arr_to_uint32_big_endian(buf.buffer.slice(0, 4));
      v[1] = uint8_arr_to_uint32_big_endian(buf.buffer.slice(4, 8));
    } else {
      v[0] = uint8_arr_to_uint32_big_endian(msg.buffer.slice(offset, offset + 4));
      v[1] = uint8_arr_to_uint32_big_endian(msg.buffer.slice( offset + 4, offset + 8 ));
    }

    method( v, k, iv );

    //out.writeUInt32BE( v[0], offset );
    //out.writeUInt32BE( v[1], offset + 4 );
    out.set(uint32_to_uint8_big_endian(v[0]), offset)
    out.set(uint32_to_uint8_big_endian(v[1]), offset + 4)

    offset += 8;
  }

  if ( skippad || encryption )
    return out;

  var pad = out[out.length - 1];
  return out.slice(0, out.length - pad);
}

/**
 * Encrypts single block of data using XTEA cipher.
 *
 * @param {Uint8Array} block  64-bit (8-bytes) block of data to encrypt
 * @param {Uint8Array} key    128-bit (16-bytes) encryption key
 * @returns {Uint8Array}  64-bit of encrypted block
 */
function encryptBlock( block, key ) {
  return doBlock( encipher, block, key );
}

/**
 * Decrypts single block of data using XTEA cipher.
 *
 * @param {Uint8Array} block  64-bit (8-bytes) block of data to encrypt
 * @param {Uint8Array} key    128-bit (16-bytes) encryption key
 * @returns {Uint8Array}  64-bit of encrypted block
 */
function decryptBlock( block, key ) {
  return doBlock( decipher, block, key );
}

/**
 * Encrypts data using XTEA cipher using specified block cipher mode of operation
 * and PKCS#7 padding.
 *
 * @param {Uint8Array} msg  Message to encrypt
 * @param {Uint8Array} key  128-bit encryption key (16 bytes)
 * @param {string} [mode=ecb]  Block cipher mode of operation (currently only 'ecb' or 'cbc')
 * @param {Uint8Array} [iv]  Optional IV
 * @param {bool}   [skippad]  Skip PKCS#7 padding postprocessing
 * @returns {Uint8Array}
 */
function encrypt( msg, key, mode, ivbuf, skippad ) {
  return doBlocks( true, msg, key, mode, ivbuf, skippad );
}

/**
 * Decrypts data using XTEA cipher using specified block cipher mode of operation
 * and PKCS#7 padding.
 *
 * @param {Uint8Array} msg  Ciphertext to decrypt
 * @param {Uint8Array} key  128-bit encryption key (16 bytes)
 * @param {string} [mode=ecb]  Block cipher mode of operation (currently only 'ecb' or 'cbc')
 * @param {Uint8Array} [iv]  Optional IV
 * @param {bool}   [skippad]  Skip PKCS#7 padding postprocessing
 * @returns {Uint8Array}
 */
function decrypt( msg, key, mode, ivbuf, skippad ) {
  return doBlocks( false, msg, key, mode, ivbuf, skippad );
}

exports.encryptBlock = encryptBlock
exports.decryptBlock = decryptBlock
exports.encrypt = encrypt
exports.decrypt = decrypt
// vim: ts=2 sts=2 sw=2 et
