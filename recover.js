import * as secp from "@noble/secp256k1";
import { sha256 } from "@noble/hashes/sha2";

console.log("hi");

async function go() {
  // const privKey = secp.utils.randomPrivateKey(); // Secure random private key
  // const msgHash_ =
  //   "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
  // const signature_ = await secp.signAsync(msgHash_, privKey); // Sync methods below
  // console.log(signature_.toCompactHex());

  const msg = "MTcyMjM2NTM0Mw==";
  const msgbuf = Buffer.from(msg, "base64");

  const msgHash = lightningHash(msgbuf);

  const sig =
    "HzrHUtPWj4eGBq7JcnskFNcHvun5SW8DYRRHqtHNSbooWgpoIUEAyE-xAbLJSGdS10wf5-FvAgVyANg1dkz5D9w=";
  const sigbuf = Buffer.from(sig, "base64");

  const sigBytes = sigbuf.slice(1);
  const recidBytes = sigbuf.slice(0, 1);
  const recid = Buffer.from(recidBytes).readUIntBE(0, 1) - 31;

  const sigNoRec = secp.Signature.fromCompact(sigBytes);
  const signature = sigNoRec.addRecoveryBit(recid);
  const pk = signature.recoverPublicKey(msgHash);

  const pubkey = pk.toHex(true);
  console.log(pubkey);
}

export function lightningHash(msg) {
  const encPrefix = new TextEncoder().encode("Lightning Signed Message:");
  const arr = new Uint8Array([...encPrefix, ...msg]);
  let shaone = sha256(arr);
  let shatwo = sha256(shaone);
  return shatwo;
}

const MAGIC_NUMBER = 31;

// args are uint8arrays, res is unit8array
export async function sign(privKey, msg) {
  const hash = lightningHash(msg);
  const sig = await secp.sign(hash, privKey);
  const sig_bytes = sig.toCompactRawBytes();
  let rid = [sig.recovery + MAGIC_NUMBER];
  return new Uint8Array([...rid, ...sig_bytes]);
}

go();
