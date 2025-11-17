import hashlib
from tinyec.ec import SubGroup, Curve
from tinyec.ec import Point



class Secp256k1:
    # Curve parameters
    p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    a  = 0
    b  = 7
    Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    byte_size = 32
    field = SubGroup(p, g =(Gx, Gy), n=n, h=1)
    curve = Curve(a, b, field, name='secp256k1')
    
    @classmethod
    def generator(cls):
        return Point(cls.curve, cls.Gx, cls.Gy)
    @classmethod
    def map_to_point(cls, seed):
        while True:
            digest = hashlib.sha256(seed).digest()
            x = int.from_bytes(digest, 'big') % cls.p

            rhs = (x**3 + cls.a *x + cls.b ) % cls.p
            if pow(rhs, (cls.p - 1) // 2, cls.p) == 1:
                y = pow(rhs, (cls.p + 1) // 4, cls.p)
                return Point(cls.curve, x, y)

            seed = hashlib.sha256(seed).digest()
    @classmethod
    def get_point(cls, x_coordinate, y_coordinate):
        return Point(cls.curve, x_coordinate, y_coordinate)
    @classmethod
    def is_on_curve(cls, point):
        x, y = point.x, point.y
        lhs = y * y % cls.curve.field.p
        rhs = (x**3 + cls.curve.a * x + cls.curve.b) % cls.curve.field.p
        is_generator = (x == cls.Gx ) and (y == cls.Gy)
        return lhs == rhs, is_generator
    @classmethod
    def array_to_point(cls, array):
        points = [] 
        for id in range(len(array)): 
            try :
                points.append(Point(cls.curve, array[id][0], array[id][1]))
            except:
                raise("point not on curve")
        return points

class Secp192r1:
    # Curve parameters
    p  = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
    a  = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
    b  = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
    Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
    n  = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
    byte_size = 24
    field = SubGroup(p, g=(Gx, Gy), n=n, h=1)
    curve = Curve(a, b, field, name='secp192r1')
    @classmethod
    def generator(cls):
        return Point(cls.curve, cls.Gx, cls.Gy)
    @classmethod
    def map_to_point(cls, seed: bytes):
        while True:
            digest = hashlib.sha256(seed).digest()
            x = int.from_bytes(digest, 'big') % cls.p

            rhs = (x**3 + cls.a *x + cls.b ) % cls.p
            if pow(rhs, (cls.p - 1) // 2, cls.p) == 1:
                y = pow(rhs, (cls.p + 1) // 4, cls.p)
                return Point(cls.curve, x, y)

            seed = hashlib.sha256(seed).digest()
    @classmethod
    def get_point(cls, x_coordinate, y_coordinate):
        return Point(cls.curve, x_coordinate, y_coordinate)
    @classmethod
    def is_on_curve(cls, point):
        x, y = point.x, point.y
        lhs = y * y % cls.curve.field.p
        rhs = (x**3 + cls.curve.a * x + cls.curve.b) % cls.curve.field.p
        is_generator = (x == cls.Gx ) and (y == cls.Gy)
        return lhs == rhs, is_generator
    @classmethod
    def array_to_point(cls, array):
        points = [] 
        for id in range(len(array)): 
            try :
                points.append(Point(cls.curve, array[id][0], array[id][1]))
            except:
                raise("point not on curve")
        return points