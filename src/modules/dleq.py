import secrets
import hashlib

class DLEQ: 
    def __init__(self, given_random_value, curve, secret):
        self.given_random_value = given_random_value
        self.curve = curve
        self.secret = secret
        
        
    def proof_gen(self): 
        curve_H = self.curve.map_to_point(self.curve.Gx.to_bytes(self.curve.byte_size, 'big') + self.curve.Gy.to_bytes(self.curve.byte_size, 'big'))

        #  Proof of knowledge of descrete log in the same curve 
        k = secrets.randbelow(self.curve.field.n )
        t = secrets.randbelow(self.curve.field.n )
        R_p = k * self.curve.generator()
        R_c = k * self.curve.generator()+ t * curve_H
        challenge = self.challenge_computation([R_p, R_c])
        sigma = (k + (challenge * self.secret)) % self.curve.field.n
        delta = (t + (challenge * self.given_random_value)) % self.curve.field.n
        
        proof = {
            "R":  [R_p.x, R_p.y], 
            "R_c": [R_c.x, R_c.y],
            "alpha": sigma, 
            "alpha_c": delta
        }
        return proof

    def challenge_computation(self, points: list): 
        input = bytes()
        for point in points: 
            if self.curve.is_on_curve(point):
                input += point.x.to_bytes(self.curve.byte_size, 'big') + point.y.to_bytes(self.curve.byte_size, 'big')
            else : 
                raise('point is not on any of the curves')
        digest = hashlib.sha256(input).digest() 
        return int.from_bytes(digest, 'big')
