var xtea = require("../xtea");
var test = require("tape");

function convert_string( s ) {
    let arrayBuffer = new ArrayBuffer(s.length * 1);
    let newUint = new Uint8Array(arrayBuffer);
    newUint.forEach((_, i) => {
        newUint[i] = s.charCodeAt(i);
    });
    return newUint;
}

function convert_hex_string( hexString ) {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

test('XTEA ECB encryption', function (t) {
    var buf = new Uint8Array([1,2,3]);
    var key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
    var enc = xtea.encrypt(buf, key);
    var dec = xtea.decrypt(enc, key);

    t.notDeepEqual(enc, buf, "ciphertext should not equal plaintext");
    t.deepEqual(dec, buf, "decrypted text should equal plaintext");

    enc = xtea.encrypt(convert_string("test vector 1"), convert_string("super secret key"));
    t.deepEqual(enc, new Uint8Array([223,83,148,252,243,87,191,226,116,252,121,16,154,53,112,203]), "test vector 1");

    enc = xtea.encrypt(convert_string("00000000"), convert_string("super secret key"));
    t.deepEqual(enc, new Uint8Array([113,181,178,30,196,40,107,136,191,240,216,226,16,148,62,88]), "test vector 2");

    enc = xtea.encrypt(convert_string("0000000000000000"), convert_string("super secret key"));
    t.deepEqual(enc, new Uint8Array([113,181,178,30,196,40,107,136,113,181,178,30,196,40,107,136,191,240,216,226,16,148,62,88]), "test vector 3");

    enc = xtea.encrypt(convert_string("0000000000000000"), convert_string("super secret key"), 'ecb', false, true);
    t.deepEqual(enc, new Uint8Array([113,181,178,30,196,40,107,136,113,181,178,30,196,40,107,136]), "test vector 4 (skipped padding)");

    t.end();
})

test('XTEA CBC encryption', function (t) {
    var buf = new Uint8Array([1,2,3]);
    var key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
    var iv  = new Uint8Array([8,7,6,5,4,3,2,1]);
    var enc = xtea.encrypt(buf, key, "cbc", iv);
    var dec = xtea.decrypt(enc, key, "cbc", iv);
    t.notDeepEqual(enc, buf, "ciphertext should not equal plaintext");
    t.deepEqual(dec, buf, "decrypted text should equal plaintext");

    enc = xtea.encrypt(convert_string("test vector 1"), convert_string("super secret key"), "cbc", convert_string("iv_value"));
    t.deepEqual(enc, new Uint8Array([125,198,23,180,230,255,169,214,221,5,37,102,118,82,92,220]), "test vector 1");

    enc = xtea.encrypt(convert_string("00000000"), convert_string("super secret key"), "cbc", convert_string("iv_value"));
    t.deepEqual(enc, new Uint8Array([203,190,233,189,122,108,38,122,69,155,94,70,225,197,145,101]), "test vector 2");

    enc = xtea.encrypt(convert_string("0000000000000000"), convert_string("super secret key"), "cbc", convert_string("iv_value"));
    t.deepEqual(enc, convert_hex_string("cbbee9bd7a6c267ad17f4720f3eb70f31707672103db54d5"), "test vector 3");
    
    enc = xtea.encrypt(convert_string("0000000000000000"), convert_string("super secret key"), "cbc", convert_string("iv_value"), true);
    t.deepEqual(enc, convert_hex_string("cbbee9bd7a6c267ad17f4720f3eb70f3"), "test vector 4 (skipped padding)");

    enc = xtea.encrypt(convert_string("0000000000000000"), convert_string("super secret key"), "cbc");
    t.deepEqual(enc, convert_hex_string("71b5b21ec4286b88920efa7cefa8b058fd5975f97b442b69"), "test vector 5 (not specified iv)");

    enc = xtea.encrypt(convert_string("0000000000000000"), convert_string("super secret key"), "cbc", false, true);
    t.deepEqual(enc, convert_hex_string("71b5b21ec4286b88920efa7cefa8b058"), "test vector 6 (not specified iv, skipped padding)");

    t.throws(function() {
        xtea.encrypt(convert_string("00000000000000"), convert_string("super secret key"), "cbc", false, true);
    }, "test vector 7 (skipped padding, invalid block length)");

    t.end();
})




