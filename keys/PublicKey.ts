import ecurve from 'ecurve';

export default class PublicKey {
    public Q: ecurve.Point;

    constructor(pubPoint: ecurve.Point) {
        this.Q = pubPoint;
    }

    public toBuffer(): Buffer {
        return this.Q.getEncoded(true);
    }
}
