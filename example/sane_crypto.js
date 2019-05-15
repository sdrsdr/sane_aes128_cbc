let sane_enc;
//this allows the test to be called from sane_aes128_cbc root folder
try {
	sane_enc=require("sane_aes128_cbc");
} catch  (e){
	sane_enc=require("../build/Release/sane_aes128_cbc");
}

let key=Buffer.from('847AF60741BD4847D883CBE67ABB459D','hex'); // 16 bytes
let iv=Buffer.from('EF47541B526BEA55178A8DC3DD76EA2F','hex');  // 16 bytes

let enc_ctx=sane_enc.getEncryptCtx(key,iv);
let txt1=Buffer.from([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]); 
let txt2=Buffer.alloc(64); 
txt2.fill('b');


console.log("txt1",txt1)
console.log("txt2",txt2)
sane_enc.Encrypt(enc_ctx,txt1);
sane_enc.Encrypt(enc_ctx,txt2);
console.log("enc1",txt1)
console.log("enc2",txt2)

let dec_ctx=sane_enc.getDecryptCtx(key,iv);
sane_enc.Decrypt(dec_ctx,txt1);
sane_enc.Decrypt(dec_ctx,txt2);
console.log("dec1",txt1);
console.log("dec2",txt2);

