import BigInteger from 'bigi';
import ecurve from 'ecurve';

export default class Signature {
  public R: Buffer;
  public s: Buffer;

  constructor(R: ecurve.Point | string, s: BigInteger | string) {
    this.R = R instanceof ecurve.Point ? R.getEncoded(true) : Buffer.from(R, 'hex');
    this.s = s instanceof BigInteger ? s.toBuffer(32) : Buffer.from(s, 'hex');
  }
}
