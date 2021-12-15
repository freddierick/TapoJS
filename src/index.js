const crypto = require('crypto');
const fetch = require('node-fetch');
const pkcs7 = require('pkcs7');
const { v4: uuidv4 } = require('uuid');

const ERROR_CODES = {
	"0": "Success",
	"-1010": "Invalid Public Key Length",
	"-1012": "Invalid terminalUUID",
	"-1501": "Invalid Request or Credentials",
	"1002": "Incorrect Request",
	"-1003": "JSON formatting error "
};

class Tapo {
    constructor(){
        this.terminalUUID = uuidv4();
    }
    async connect(ip, email, password){
        this.ipAddress = ip;

        const { publicKey, privateKey } = await new Promise((res, rej) => {
            crypto.generateKeyPair('rsa', {
                modulusLength: 1024,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs1',
                    format: 'pem',                }
              }, (err, publicKey, privateKey) => {
                res({publicKey, privateKey});
              });
        });
        
        this.encodedPassword = Buffer.from(password).toString("base64");
        this.encodedEmail  = crypto.createHash('sha1').update(email).digest();

        let sb = ""
        for (let i = 0; i < this.encodedEmail.length; i++) {
			let b = this.encodedEmail[i]
			let hex_string = (b & 255).toString(16)
			if (hex_string.length == 1){
                sb += "0"
				sb += hex_string
            } else{
				sb += hex_string
            };
        };

        this.encodedEmail = sb;
        this.encodedEmail  = Buffer.from(this.encodedEmail).toString("base64");
        this.keys = { publicKey, privateKey };

        await this.handshake();
        await this.login();

        return this;
    };

    async handshake() {
        const URL = `http://${this.ipAddress}/app`
		const Payload = {
			"method":"handshake",
			"params":{
				"key": this.keys.publicKey,
				"requestTimeMils": Date.now()
			},
		};
	    const res = await fetch(URL, { method: "POST", body: JSON.stringify(Payload) });
        const json = await res.json();
        const encryptedKey = json["result"]["key"];
        this.tpLinkCipher = await this._decodeHandshakeKey(encryptedKey)
        this.cookie = res.headers.get("Set-Cookie");
        this.cookie = this.cookie.substring(0, this.cookie.length - 13);
    };

    async login() {
        const URL = `http://${this.ipAddress}/app`
		const Payload = {
			"method":"login_device",
			"params":{
				"username": this.encodedEmail,
				"password": this.encodedPassword
			},
			"requestTimeMils": Date.now(),
		};

        const EncryptedPayload = await this._encryptPayload(JSON.stringify(Payload));

        const SecurePassthroughPayload = {
			"method": "securePassthrough",
			"params": {
				"request": EncryptedPayload
			}
		}

	    const res = await fetch(URL, { method: "POST", headers: { "Cookie": this.cookie }, body: JSON.stringify(SecurePassthroughPayload) });

        const json = await res.json();

        const decrypted = this._decryptPayload(Buffer.from(json["result"]["response"], 'base64'));
        const decryptedJson = JSON.parse(decrypted.toString());
        if (decryptedJson["error_code"] != 0) throw new Error(ERROR_CODES[decryptedJson["error_code"]]);
        this.token = decryptedJson["result"]["token"];
    };

    async _decodeHandshakeKey(key){
        const decrypted = crypto.privateDecrypt(
            {
                key: this.keys.privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING
            },
            Buffer.from(key, 'base64')
        );
        this.key = decrypted.subarray(0, 16);
        this.iv = decrypted.subarray(16, 32);
    };

    mime_encoder(to_encode){
        let encoded_list = Array.from(Buffer.from(to_encode).toString('base64'));
        let count = 0
        for (let index = 76; index < encoded_list.length - 1; index = index + 76) {
            encoded_list.splice(index + count, 0, '\r\n')
            count += 1
        }
        return encoded_list.join('');
    };

    _encryptPayload(payload){
        const data = pkcs7.pad(Buffer.from(payload));      
        const cipher = crypto.createCipheriv('aes-128-cbc' , this.key, this.iv);
        let encrypted = cipher.update(Buffer.from(data));
        return this.mime_encoder(encrypted);
    };

    _decryptPayload(payload){
        const decipher = crypto.createDecipheriv('AES-128-CBC', this.key, this.iv);  
        return Buffer.concat([decipher.update(payload), decipher.final()]);
    };

    async _sendPayloadToDevice(Payload){
        const URL = `http://${this.ipAddress}/app?token=${this.token}`
        const EncryptedPayload = await this._encryptPayload(JSON.stringify(Payload));
        const SecurePassthroughPayload = {
			"method": "securePassthrough",
			"params": {
				"request": EncryptedPayload
			}
		};
        const res = await fetch(URL, { method: "POST", headers: { "Cookie": this.cookie }, body: JSON.stringify(SecurePassthroughPayload) });
        const json = await res.json();
        return this._decryptPayload(Buffer.from(JSON.stringify(json["result"]["response"]), 'base64'));
    };

    turnOn(){
        return this._sendPayloadToDevice({
			"method": "set_device_info",
			"params":{
				"device_on": true
			},
			"requestTimeMils": Date.now(),
			"terminalUUID": this.terminalUUID
		});
    };

    turnOff(){
        return this._sendPayloadToDevice({
			"method": "set_device_info",
			"params":{
				"device_on": false
			},
			"requestTimeMils": Date.now(),
			"terminalUUID": this.terminalUUID
		});
    };
};

module.exports = Tapo;