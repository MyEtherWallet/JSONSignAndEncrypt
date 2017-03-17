const crypto = require("crypto");
const eccrypto = require("eccrypto");
const signingAlgo = 'sha256';
var getDeterministicValues = function(JSONObj) {
    var keys = [];
    for (var key in JSONObj)
        if (JSONObj.hasOwnProperty(key)) keys.push(key);
    keys.sort();
    var values = [];
    for (var i in keys) {
        if (typeof JSONObj[keys[i]] === 'object') values.push(getDeterministicValues(JSONObj[keys[i]]));
        else values.push(JSONObj[keys[i]]);
    }
    return values.join('');
}
var encryptedToHex = function(sig) {
    return {
        iv: sig.iv.toString('hex'),
        ephemPublicKey: sig.ephemPublicKey.toString('hex'),
        ciphertext: sig.ciphertext.toString('hex'),
        mac: sig.mac.toString('hex')
    }
}
var hexToEncrypted = function(sigObj) {
    return {
        iv: Buffer(sigObj.iv, 'hex'),
        ephemPublicKey: Buffer(sigObj.ephemPublicKey, 'hex'),
        ciphertext: Buffer(sigObj.ciphertext, 'hex'),
        mac: Buffer(sigObj.mac, 'hex')
    }
}
var getPublicKey = function(privKey) {
    return eccrypto.getPublic(privKey);
}
var JSONObjectToString = function(JSONObj) {
    return JSON.stringify(JSONObj);
}
var stringToJSONObject = function(str) {
    return JSON.parse(str);
}
var stringToHash = function(str) {
    return crypto.createHash(signingAlgo).update(str).digest();
}
var getSignature = function(str, privKey) {
    return eccrypto.sign(privKey, stringToHash(str)).then(function(sig) {
        return sig.toString('hex');
    });
}
var verifySignature = function(str, sig, pubKey) {
    sig = Buffer(sig, 'hex');
    return eccrypto.verify(pubKey, stringToHash(str), sig).then(function() {
        return true;
    }).catch(function() {
        return false;
    });
}
var encrypt = function(JSONObj, pubKey) {
    var str = JSONObjectToString(JSONObj);
    return eccrypto.encrypt(pubKey, Buffer(str)).then(function(encrypted) {
        return encryptedToHex(encrypted);
    });
}
var decrypt = function(encryptedStr, privKey) {
    encryptedBuffer = hexToEncrypted(encryptedStr);
    return eccrypto.decrypt(privKey, encryptedBuffer).then(function(str) {
        return stringToJSONObject(str.toString());
    });
}
var signAndEncrypt = function(JSONObj, privKeyClient, pubKeyServer) {
    var detValues = getDeterministicValues(JSONObj);
    return getSignature(detValues, privKeyClient).then(function(sig) {
        JSONObj.sig = sig;
        return encrypt(JSONObj, pubKeyServer).then(function(encrypted) {
            return encrypted;
        });
    });
}
var decryptAndVerify = function(encryptedStr, privKeyServer, pubKeyClient) {
    encryptedBuffer = hexToEncrypted(encryptedStr);
    return eccrypto.decrypt(privKeyServer, encryptedBuffer).then(function(str) {
        var JSONObj = stringToJSONObject(str.toString());
        var sig = JSONObj.sig;
        delete JSONObj.sig;
        var detValues = getDeterministicValues(JSONObj);
        return verifySignature(detValues, sig, pubKeyClient).then(function() {
            return JSONObj;
        }).catch(function() {
            return false;
        });
    });
}
module.exports = {
    getDeterministicValues: getDeterministicValues,
    JSONObjectToString: JSONObjectToString,
    stringToJSONObject: stringToJSONObject,
    stringToHash: stringToHash,
    getSignature: getSignature,
    verifySignature: verifySignature,
    encrypt: encrypt,
    decrypt: decrypt,
    signAndEncrypt: signAndEncrypt,
    decryptAndVerify: decryptAndVerify,
    getPublicKey: getPublicKey
}
