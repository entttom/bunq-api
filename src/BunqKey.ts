"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BunqKey = void 0;
var NodeRSA = require('node-rsa');
var fs = require("fs-extra");
var BunqKey = /** @class */ (function () {
    function BunqKey(privateKeyPem) {
        this.key = new NodeRSA(privateKeyPem, { signingScheme: 'pkcs1-sha256', env: 'node' });
    }
    BunqKey.createNew = function () {
        /* istanbul ignore next */
        {
            var aKey = new NodeRSA({
                b: 2048,
                encryptionScheme: 'pkcs1',
                signingScheme: 'pkcs1-sha256'
            });
            var privateKeyString = aKey.exportKey('pkcs8-private-pem');
            return new this(privateKeyString);
        }
    };
    BunqKey.createFromPrivateKeyFile = function (pemFilename) {
        var buffer = fs.readFileSync(pemFilename);
        return new this(buffer.toString());
    };
    BunqKey.prototype.toPublicKeyString = function () {
        return this.key.exportKey('pkcs8-public-pem');
    };
    BunqKey.prototype.toPrivateKeyString = function () {
        return this.key.exportKey('pkcs8-private-pem');
    };
    BunqKey.prototype.signApiCall = function (options) {
        var stringToSign = this.createStringToSign(options);
        //console.log("signApiCall:"+stringToSign);
        //let key = new NodeRSA(this.privateKey, {signingScheme: 'pkcs1-sha256', env: 'node'});
        return this.key.sign(stringToSign, 'base64', 'utf8');
        // const sign = crypto.createSign('sha256');
        // sign.update(stringToSign);
        // return sign.sign({
        //   key: this.privateKey,
        //   passphrase: ""
        // }, "base64");
    };
    BunqKey.prototype.verifySigWithPubkey = function (options) {
        var pubKey = new NodeRSA();
        pubKey.importKey(this.toPublicKeyString(), 'public');
        var optionsSig = options.headers['X-Bunq-Client-Signature'];
        delete options.headers['X-Bunq-Client-Signature'];
        var stringToSign = this.createStringToSign(options);
        options.headers['X-Bunq-Client-Signature'] = optionsSig;
        //console.log("verify:"+stringToSign);
        return pubKey.verify(stringToSign, optionsSig, 'utf8', 'base64');
    };
    BunqKey.prototype.createStringToSign = function (options) {
	var stringToSign = ""       
       // var stringToSign = "options.method + " "";
       /* // let endPoint:string = options.uri;
        //if(options.uri.indexOf("bunq.com") != -1)
        // endPoint = (options.uri.split("bunq.com"))[1];
        stringToSign += (options.uri.split("bunq.com"))[1];
        stringToSign += "\n";
        // We need to order the headers
        var orderedHeaders = BunqKey.orderKeys(options.headers);
        Object.keys(orderedHeaders).forEach(function (key) {
            //if (key.startsWith("X-Bunq-") || key == "Cache-Control" || key == "User-Agent")
            stringToSign += key + ": " + orderedHeaders[key] + "\n";
        });
        stringToSign += "\n";
        */
        if (options.body) {
            stringToSign += options.body.toString();
            console.log(options.body.toString())
        }
        console.log("string to sign: " + stringToSign)
        return stringToSign;
    };
    // credit to http://stackoverflow.com/questions/9658690/is-there-a-way-to-sort-order-keys-in-javascript-objects
    BunqKey.orderKeys = function (obj) {
        var keys = Object.keys(obj).sort(function keyOrder(k1, k2) {
            if (k1 < k2)
                return -1;
            else
                return +1;
        });
        var after = {};
        for (var i = 0; i < keys.length; i++) {
            after[keys[i]] = obj[keys[i]];
            delete obj[keys[i]];
        }
        for (var i = 0; i < keys.length; i++) {
            obj[keys[i]] = after[keys[i]];
        }
        return obj;
    };
    return BunqKey;
}());
exports.BunqKey = BunqKey;
//# sourceMappingURL=BunqKey.js.map
