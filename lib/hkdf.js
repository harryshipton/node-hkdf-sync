//
// a straightforward implementation of HKDF
//
// https://tools.ietf.org/html/rfc5869
//

var crypto = require("crypto");

function zeros(length) {
  var buf = Buffer.alloc(length, 0);

  return buf.toString();
}
// imk is initial keying material
function HKDF(hashAlg, salt, ikm) {
  this.hashAlg = hashAlg;

  // create the hash alg to see if it exists and get its length
  var hash = crypto.createHash(this.hashAlg);
  this.hashLength = hash.digest().length;

  this.salt = salt || zeros(this.hashLength);
  this.ikm = ikm;

  // now we compute the PRK
  var hmac = crypto.createHmac(this.hashAlg, this.salt);
  hmac.update(this.ikm);
  this.prk = hmac.digest();
}

HKDF.prototype = {
  derive: function(info, size) {
    var prev = Buffer.alloc(0, 0);
    var output;
    var buffers = [];
    var num_blocks = Math.ceil(size / this.hashLength);
    var infoBuf = Buffer.from(info, 'binary');

    for (var i=0; i<num_blocks; i++) {
      var hmac = crypto.createHmac(this.hashAlg, this.prk);
      // XXX is there a more optimal way to build up buffers?
      var input = Buffer.concat([
        prev,
        infoBuf,
        Buffer.alloc(1, i+1)
      ]);
      hmac.update(input);
      prev = hmac.digest();
      buffers.push(prev);
    }
    output = Buffer.concat(buffers, size);
    return output;
  }
};

module.exports = HKDF;
