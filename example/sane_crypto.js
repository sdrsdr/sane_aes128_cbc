let sane_enc=require("sane_aes128_cbc");

let key=Buffer.from('847AF60741BD4847D883CBE67ABB459D','hex'); // 16 bytes
let iv=Buffer.from('EF47541B526BEA55178A8DC3DD76EA2F','hex');  // 16 bytes

let enc_ctx=sane_enc.getEncryptCtx(key,iv);
let txt1=Buffer.alloc(32); 
txt1.fill('a');
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

