import BigInteger from 'bigi';
import ecurve from 'ecurve';

export default class Signature {
  public R: Buffer;
  public s: Buffer;

  constructor(R: ecurve.Point, s: BigInteger) {
    this.R = R.getEncoded(true);
    this.s = s.toBuffer(32);
  }
}
