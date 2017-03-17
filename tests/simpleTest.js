var chai = require('chai');
var signUtils = require("../index.js");
var crypto = require("crypto");
var assert = chai.assert;

describe('deterministic string test', function() {
    it('should return sort values by keys', function() {
        var testObj1 = {
            b: "2",
            c: "3",
            a: "1",
            d: "4"
        };
        assert.equal(signUtils.getDeterministicValues(testObj1), '1234');
    });
    it('should return sort values by keys - recursive', function() {
        var testObj1 = {
            b: "2",
            c: "3",
            a: {
                f: "6",
                e: "5",
                g: {
                    h: "8",
                    i: {
                        k: "11",
                        j: "10",
                        l: "12",
                    }
                },
            },
            d: "4"
        };
        assert.equal(signUtils.getDeterministicValues(testObj1), '568101112234');
    });
});
describe('hashing alogo test', function() {
    it('should hash string', function() {
        assert.equal(signUtils.stringToHash("this is epic test string").toString('hex'), '28118cd4b47763e15b4aaf0f34e64dfbc099a744cd2bda6be7257dfb2f6356f6');
    });
});
describe('encrypt decrypt test', function() {
    it('should properly encrypt and decrypt 100 tests', function(done) {
        var privateKeyA = crypto.randomBytes(32);
        var publicKeyA = signUtils.getPublicKey(privateKeyA);
        var randStrings = {};
        for (var i = 0; i < 100; i++) randStrings[i] = crypto.randomBytes(32).toString('hex');
        signUtils.encrypt(randStrings, publicKeyA).then(function(encrypted) {
            signUtils.decrypt(encrypted, privateKeyA).then(function(decrypted) {
                for (var key in decrypted) assert.equal(randStrings[key], decrypted[key]);
                done();
            });
        });
    });
    it('Another test just to be safe', function(done) {
        var privateKeyA = crypto.randomBytes(32);
        var publicKeyA = signUtils.getPublicKey(privateKeyA);
        var randStrings = {};
        for (var i = 0; i < 100; i++) randStrings[i] = crypto.randomBytes(32).toString('hex');
        signUtils.encrypt(randStrings, publicKeyA).then(function(encrypted) {
            signUtils.decrypt(encrypted, privateKeyA).then(function(decrypted) {
                for (var key in decrypted) assert.equal(randStrings[key], decrypted[key]);
                done();
            });
        });
    });
});
describe('signature tests', function() {
    it('sign and verify 100 tests', function(done) {
        var privateKeyA = crypto.randomBytes(32);
        var publicKeyA = signUtils.getPublicKey(privateKeyA);
        var randStrings = [];
        for (var i = 0; i < 100; i++) randStrings.push(crypto.randomBytes(32).toString('hex'));
        var counter = 0;
        var _signVerify = function(str, privKey, pubKey) {
            signUtils.getSignature(str, privKey).then(function(sig) {
                signUtils.verifySignature(str, sig, publicKeyA).then(function(result) {
                    assert.equal(result, true);
                    counter++;
                    if (counter == randStrings.length) done();
                });
            });
        }
        for (var i in randStrings) _signVerify(randStrings[i], privateKeyA, publicKeyA);
    });
});
describe('encrypt and decrypt json object', function() {
    it('sign encrypt, decrypt and verify', function(done) {
        var clientPrivKey = crypto.randomBytes(32);
        var clientpubKey = signUtils.getPublicKey(clientPrivKey);
        var serverPrivKey = crypto.randomBytes(32);
        var serverPubKey = signUtils.getPublicKey(serverPrivKey);
        var randStrings = {};
        for (var i = 0; i < 100; i++) randStrings[crypto.randomBytes(32).toString('hex')] = crypto.randomBytes(32).toString('hex');
        signUtils.signAndEncrypt(randStrings, clientPrivKey, serverPubKey).then(function(encrypted) {
            signUtils.decryptAndVerify(encrypted, serverPrivKey, clientpubKey).then(function(result) {
            	delete randStrings.sig;
                for (var key in randStrings) assert.equal(randStrings[key], result[key]);
                done();
            });
        });
    });
});
