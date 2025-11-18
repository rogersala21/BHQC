import secrets
import hashlib

class DLEQ: 
    def __init__(self,curve ):
        self.curve = curve
        self.curve_H = self.curve.map_to_point(self.curve.Gx.to_bytes(self.curve.byte_size, 'big') + self.curve.Gy.to_bytes(self.curve.byte_size, 'big'))

        
    def proof_gen(self, given_random_value, secret ): 
        #  Proof of knowledge of descrete log in the same curve 
        k = secrets.randbelow(self.curve.field.n )
        t = secrets.randbelow(self.curve.field.n )
        R_p = k * self.curve.generator()
        R_c = k * self.curve.generator() + t * self.curve_H
        challenge = self.challenge_computation([R_p, R_c])
        sigma = (k + (challenge * secret)) % self.curve.field.n
        delta = (t + (challenge * given_random_value)) % self.curve.field.n
        
        proof = {
            "R":  [R_p.x, R_p.y], 
            "R_c": [R_c.x, R_c.y],
            "alpha": sigma, 
            "alpha_c": delta
        }
        return proof

    def proof_verification(self, proof, commitment, point):
        R = self.curve.get_point(proof["R"][0], proof["R"][1])
        R_c = self.curve.get_point(proof["R_c"][0], proof["R_c"][1])
        challenge = self.challenge_computation([R, R_c]) 
        lhs = proof["alpha"] * self.curve.generator() 
        rhs = R + challenge * point
        assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment"
        rhs = proof["alpha"] * self.curve.generator() + proof["alpha_c"] * self.curve_H
        lhs = R_c + challenge * commitment
        assert lhs.x == rhs.x and lhs.y == rhs.y, "Check failed for the equality of private key and the commitment with blinding factor"
        print(f"DLEQ verified for curve {self.curve.name}")



    def challenge_computation(self, points: list): 
        input = bytes()
        for point in points: 
            if self.curve.is_on_curve(point):
                input += point.x.to_bytes(self.curve.byte_size, 'big') + point.y.to_bytes(self.curve.byte_size, 'big')
            else : 
                raise('point is not on any of the curves')
        digest = hashlib.sha256(input).digest() 
        return int.from_bytes(digest, 'big')
