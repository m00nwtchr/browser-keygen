const { generateKeyPair } = require('.');
// generateKeyPair('rsa', {
// 	modulusLength: 4096,
// 	publicKeyEncoding: {
// 		type: 'spki',
// 		format: 'pem'
// 	},
// 	privateKeyEncoding: {
// 		type: 'pkcs8',
// 		format: 'pem'
// 	}
// }, (err, publicKey, privateKey) => {
// 	console.log(publicKey);
// 	console.log(privateKey);
// });

generateKeyPair('ec', {
	namedCurve: "p-256",
	publicKeyEncoding: {
		type: 'spki',
		format: 'pem'
	},
	privateKeyEncoding: {
		type: 'pkcs8',
		format: 'pem'
	}
}, (err, publicKey, privateKey) => {
	console.log(publicKey);
	console.log(privateKey);
});