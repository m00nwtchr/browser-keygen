const crypto = require("crypto");

function ab2str(buf) {
	return String.fromCharCode.apply(null, new Uint8Array(buf));
}

function toPem(exported, type) {
	const exportedAsString = ab2str(exported);
	const exportedAsBase64 = window.btoa(exportedAsString);
	const pemExported = `-----BEGIN ${type} KEY-----\n${exportedAsBase64}\n-----END ${type} KEY-----`;

	return pemExported;
}

if (typeof crypto.generateKeyPairSync === 'function') {
	exports.generateKeyPair = crypto.generateKeyPair;
	exports.generateKeyPairSync = crypto.generateKeyPairSync;
} else {
	exports.generateKeyPairSync = function () {
		throw new Error("Sorry, the WebCryptoAPI doesn't have a synchronous version");
	}
	exports.generateKeyPair = function (type, options, callback) {
		let algo;
		switch (type) {
			case ("rsa"):
				algo = {
					name: "RSA-PSS",
					modulusLength: options.modulusLength,
					publicExponent: new Uint8Array([1, 0, 1]),
					hash: "SHA-256"
				};
				break;

			case ("ec"):
				algo = {
					name: "ECDH",
					namedCurve: (() => {
						switch (options.namedCurve) {
							case ("secp256k1"):
								return "P-256";
							case ("secp384r1"):
								return "P-384";
							case ("secp521r1"):
								return "P-521";
						}
					})()
				};
				break;
		}

		if (options.publicKeyEncoding.format === "der" || options.privateKeyEncoding.format === "der") {
			throw new Error("DER is currently not supported!");
		}

		window.crypto.subtle.generateKey(
			algo,
			true,
			["sign", "verify"]
		).then((keyPair) => {
			Promise.all([
				window.crypto.subtle.exportKey(
					options.publicKeyEncoding.type,
					keyPair.publicKey
				),
				window.crypto.subtle.exportKey(
					options.privateKeyEncoding.type,
					keyPair.privateKey
				)
			]).then((keyPair) => {
				if (options.publicKeyEncoding.format === "pem") {
					keyPair[0] = toPem(keyPair[0], "PUBLIC")
				}
				if (options.privateKeyEncoding.format === "pem") {
					keyPair[1] = toPem(keyPair[1], "PRIVATE")
				}
				return keyPair;
			}).then((keyPair) => {
				callback(null, keyPair[0], keyPair[1]);
			}).catch((err) => {
				callback(err, null);
			});
		});
	}
}