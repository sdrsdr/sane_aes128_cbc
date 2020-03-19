export function getEncryptCtx(cryptoKey:Buffer, cryptoIv:Buffer):Buffer;
export function getDecryptCtx(cryptoKey:Buffer, cryptoIv:Buffer):Buffer;
export function Decrypt(decryptCtx:Buffer, chunkBuff:Buffer):void;
export function Encrypt(encryptCtx:Buffer, chunkBuff:Buffer):void;
