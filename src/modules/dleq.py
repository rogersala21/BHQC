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
        random_for_pubkey = secrets.randbelow(self.curve.field.n )
        random_for_commitment = secrets.randbelow(self.curve.field.n )
        proof_point_public_key = random_for_pubkey * self.curve.generator()
        proof_point_commitment = random_for_commitment * self.curve.generator()+ random_for_commitment * curve_H
        challenge = self.challenge_computation([proof_point_public_key, proof_point_commitment])
        alpha_public_key_point = (random_for_pubkey + (challenge * self.secret)) % self.curve.field.n
        alpha_commitment = (random_for_commitment + (challenge * self.given_random_value)) % self.curve.field.n
        
        proof = {
            "R":  [proof_point_public_key.x, proof_point_public_key.y], 
            "R_c": [proof_point_commitment.x, proof_point_commitment.y],
            "alpha": alpha_public_key_point, 
            "alpha_c": alpha_commitment
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
