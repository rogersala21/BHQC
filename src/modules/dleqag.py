import secrets
import hashlib
import math

class DLEQAG:
    def __init__(self, b_x: int, b_f: int, b_c: int, number_of_chunks: int, secret_range: int, HSCurve, LSCurve):
        self.b_x = b_x
        self.b_f = b_f
        self.b_c = b_c
        self.b_g = math.log2(LSCurve.field.n)
        assert(b_x + b_f + b_c <= self.b_g -1)
        self.number_of_chunks = number_of_chunks
        self.secret_range = secret_range
        self.MAX_ITER = 100
        #  Curve with the higher security (HSC)
        self.HSCurve = HSCurve
        #  Curve with the lower security (LSC)
        self.LSCurve = LSCurve
    
    def proof_gen(self, secret: int):
        K_LS, K_HS, z, s_LS, s_HS, C_LS_proof, C_HS_proof = [], [], [], [], [], [], []
        r_HS, r_LS = [], []
        HSCurve_H = self.HSCurve.H()
        LSCurve_H = self.LSCurve.map_to_point(self.LSCurve.Gx.to_bytes(self.LSCurve.byte_size, 'big') + self.LSCurve.Gy.to_bytes(self.LSCurve.byte_size, 'big'))
        assert secret <= self.secret_range

        secret_chunks = self.value_segmentation(secret)
        for chunk in range(self.number_of_chunks):
            r_HS.append(secrets.randbelow(self.HSCurve.field.n ) )
            r_LS.append(secrets.randbelow(self.LSCurve.field.n ) )
            if chunk == 0 :
                r_HS_summed = r_HS[chunk]
                r_LS_summed = r_LS[chunk]
                C_HS_summed = secret_chunks[chunk] * self.HSCurve.generator() + HSCurve_H * r_HS[chunk]
                C_LS_summed = secret_chunks[chunk] * self.LSCurve.generator() + LSCurve_H * r_LS[chunk]
                p_LS_summed = secret_chunks[chunk] * self.LSCurve.generator()
                p_HS_summed = secret_chunks[chunk] * self.HSCurve.generator()

            else: 
                r_HS_summed = (r_HS[chunk] * (2 ** (chunk * self.b_x))+ r_HS_summed) % self.HSCurve.field.n 
                r_LS_summed = (r_LS[chunk] * (2 ** (chunk * self.b_x))+ r_LS_summed) % self.LSCurve.field.n
                C_HS_summed += secret_chunks[chunk] * (2 ** (chunk * self.b_x)) * self.HSCurve.generator() + HSCurve_H * r_HS[chunk] * (2 ** (chunk * self.b_x))
                C_LS_summed += secret_chunks[chunk] * (2 ** (chunk * self.b_x)) * self.LSCurve.generator() + LSCurve_H * r_LS[chunk] * (2 ** (chunk * self.b_x))
                p_LS_summed += secret_chunks[chunk] * (2 ** (chunk * self.b_x)) * self.LSCurve.generator()
                p_HS_summed += secret_chunks[chunk] * (2 ** (chunk * self.b_x)) * self.HSCurve.generator()

            C_LS_proof.append([(secret_chunks[chunk] * self.LSCurve.generator() + LSCurve_H * r_LS[chunk]).x, (secret_chunks[chunk] * self.LSCurve.generator() + LSCurve_H * r_LS[chunk]).y])
            C_HS_proof.append([(secret_chunks[chunk] * self.HSCurve.generator() + HSCurve_H * r_HS[chunk]).x, (secret_chunks[chunk] * self.HSCurve.generator() + HSCurve_H * r_HS[chunk]).y])

            for i in range(self.MAX_ITER):
                # Generate fresh randomness
                t_HS = secrets.randbelow(self.HSCurve.field.n)
                t_LS = secrets.randbelow(self.LSCurve.field.n)
                k = secrets.randbelow(2 ** (self.b_x + self.b_c + self.b_f) -1)

                # Commitments in BTC curve
                K_HS_temp = k * self.HSCurve.generator() + t_HS * HSCurve_H

                # Commitments in NIST curve
                K_LS_temp = k * self.LSCurve.generator() + t_LS * LSCurve_H

                # Curve challenge
                curve_challenge = self.challenge_computation([K_HS_temp, K_LS_temp]) >> (256 - self.b_c) 

                # Compute z
                z_temp = k + curve_challenge * secret_chunks[chunk] 
                if 2** (self.b_x + self.b_c) <= z_temp and z_temp < 2** (self.b_x+ self.b_c + self.b_f ) -1 :
                    s_HS.append((t_HS + curve_challenge * r_HS[chunk]) % self.HSCurve.field.n)
                    s_LS.append((t_LS + curve_challenge * r_LS[chunk]) % self.LSCurve.field.n)
                    K_LS.append([K_LS_temp.x, K_LS_temp.y])
                    K_HS.append([K_HS_temp.x, K_HS_temp.y])
                    z.append(z_temp)
                    break
            if (i > self.MAX_ITER):
                raise ValueError("Too many iterations in proof generation")
        C_HS = secret * self.HSCurve.generator() + (HSCurve_H * r_HS_summed)
        assert C_HS_summed.x == C_HS.x and C_HS.y == C_HS_summed.y , "the addition of chunks does not add up in the commitments"
        P_HS = secret * self.HSCurve.generator() 
        assert P_HS.x == p_HS_summed.x and P_HS.y == p_HS_summed.y , "The addition of the chunks doesn't add up to the public key"
        P_LS = secret * self.LSCurve.generator() 
        assert P_LS.x == p_LS_summed.x and P_LS.y == p_LS_summed.y , "The addition of the chunks doesn't add up to the public key"
        C_LS = secret * self.LSCurve.generator() + (LSCurve_H * r_LS_summed)
        assert C_LS_summed.x == C_LS.x and C_LS.y == C_LS_summed.y , "the addition of chunks does not add up in the commitments"



        # Proof parameters 
        proof = {
            "pub_key_HS": [P_HS.x, P_HS.y],
            "pub_key_LS": [P_LS.x, P_LS.y],
            "X_HS": [C_HS_summed.x, C_HS_summed.y], 
            "X_LS": [C_LS_summed.x, C_LS_summed.y],
            "r_HS": r_HS_summed,
            "r_LS": r_LS_summed,
            "K_HS": K_HS,
            "K_LS": K_LS,
            "C_LS": C_LS_proof,
            "C_HS": C_HS_proof,
            "z": z, 
            "s_LS": s_LS,
            "s_HS": s_HS, 
        }
        bulletproof_input = {
            "private_key_chunks": secret_chunks, 
            "random_chunks": r_HS
        }
        # zkSNARK proof parameters 
        snark_input = {
            "pub_key_point": points_to_str([P_HS.x, P_HS.y]),
            "private_key": str(secret), 
            "private_key_range": str(self.secret_range)
        }
        return proof, snark_input, bulletproof_input

    def proof_verification(self, proof):
        s_192 = proof["s_192"]
        s_256 = proof["s_256"]
        z = proof["z"]
        C_256 = self.HSCurve.array_to_point(proof["C_256"])
        HSCurve_H = self.HSCurve.H()
        LSCurve_H = self.LSCurve.H()
        K_192 = self.LSCurve.array_to_point(proof["K_192"])
        C_192 = self.LSCurve.array_to_point(proof["C_192"])
        K_256 = self.HSCurve.array_to_point(proof["K_256"])
            # ====== Check the transitions on chunks ==========  
        for id in range(self.number_of_chunks):
            curve_challenge = self.challenge_computation([K_256[id], K_192[id]]) >> (256 - self.b_c) 
            assert    2** (self.b_x + self.b_c) <= z[id] and z[id] < 2** (self.b_x+ self.b_c + self.b_f ) -1 , "z is out of range"

            #  Check the signature validity
            # ===== Verification on weak curve (per paper: s_v * G192 == R'_v + m * C'_v) =====
            lhs_weak = self.LSCurve.generator()  * z[id] + s_192[id] * LSCurve_H
            rhs_weak = K_192[id] + curve_challenge * C_192[id]
            assert lhs_weak.x == rhs_weak.x and lhs_weak.y == rhs_weak.y, "Weak-curve check failed for the transition between curves"


            # ===== Verification on higher security curve transition to the lower security curve  =====

            lhs_btc = self.HSCurve.generator() * z[id] + s_256[id] * HSCurve_H
            rhs_btc = K_256[id] + curve_challenge * C_256[id]
            assert lhs_btc.x == rhs_btc.x and lhs_btc.y == rhs_btc.y, "BTC-curve check failed on the transition between curves"

        print("Proof verified for discrete logarithm equality across groups.")
  
    def value_segmentation(self, value): 
        assert value <= self.secret_range 
        value_bytes = value.to_bytes(self.LSCurve.byte_size, 'big')

        # Calculate chunk size in bytes
        chunk_size = self.b_x // 8  # Use integer division

        chunks = []
        for i in range(self.number_of_chunks):
            start = i * chunk_size
            end = (i + 1) * chunk_size
            chunk = value_bytes[start:end]
            chunks.append(int.from_bytes(chunk, 'big'))

        # Return chunks in MSB-first order
        return chunks[::-1]
    def challenge_computation(self, points: list): 
        input = bytes()
        for point in points: 
            if self.HSCurve.is_on_curve(point):
                input += point.x.to_bytes(self.HSCurve.byte_size, 'big') + point.y.to_bytes(self.HSCurve.byte_size, 'big')
            elif self.LSCurve.is_on_curve(point):
                input += point.x.to_bytes(self.LSCurve.byte_size, 'big') + point.y.to_bytes(self.LSCurve.byte_size, 'big')
            else : 
                raise('point is not on any of the curves')
        digest = hashlib.sha256(input).digest() 
        return int.from_bytes(digest, 'big')
    
def points_to_str(input):
    converted = []
    for element in input:
        if type(element) == list :
            # We have a list of points
            converted.append([str(element[0]), str(element[1])])
        elif type(element) == int :
            converted.append(str(element))
    return converted


