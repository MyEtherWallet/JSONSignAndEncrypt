var signUtils = require("../index.js");
var crypto = require("crypto");
var objectToEncrypt = {
    "glossary": {
        "title": "example glossary",
        "GlossDiv": {
            "title": "S",
            "GlossList": {
                "GlossEntry": {
                    "ID": "SGML",
                    "SortAs": "SGML",
                    "GlossTerm": "Standard Generalized Markup Language",
                    "Acronym": "SGML",
                    "Abbrev": "ISO 8879:1986",
                    "GlossDef": {
                        "para": "A meta-markup language, used to create markup languages such as DocBook.",
                        "GlossSeeAlso": ["GML", "XML"]
                    },
                    "GlossSee": "markup"
                }
            }
        }
    }
}

var clientPrivKey = crypto.randomBytes(32);
var clientpubKey = signUtils.getPublicKey(clientPrivKey);
var serverPrivKey = crypto.randomBytes(32);
var serverPubKey = signUtils.getPublicKey(serverPrivKey);

//signing and encrypting
signUtils.signAndEncrypt(objectToEncrypt, clientPrivKey, serverPubKey).then(function(encrypted) {
    console.log(encrypted);
    //decrypting and verifying 
    signUtils.decryptAndVerify(encrypted, serverPrivKey, clientpubKey).then(function(decrypted) {
        //encrypted is the encrypted object
        console.log(decrypted);
    }).catch(function(err) {
        //will throw error on verification failure
    });

});
