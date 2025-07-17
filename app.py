import hashlib
import random
import base64
from flask import Flask, render_template_string, request

app = Flask(__name__)

# Elliptic Curve Functions (unchanged)
def find_inverse(number, modulus):
    return pow(number, -1, modulus)

class Point:
    def __init__(self, x, y, curve_config):
        a = curve_config['a']
        b = curve_config['b']
        p = curve_config['p']
        if (y ** 2) % p != (x ** 3 + a * x + b) % p:
            raise Exception("The point is not on the curve")
        self.x = x
        self.y = y
        self.curve_config = curve_config

    def is_equal_to(self, point):
        return self.x == point.x and self.y == point.y

    def add(self, point):
        p = self.curve_config['p']
        if self.is_equal_to(point):
            slope = (3 * point.x ** 2 + self.curve_config['a']) * find_inverse(2 * point.y, p) % p
        else:
            slope = (point.y - self.y) * find_inverse(point.x - self.x, p) % p
        x = (slope ** 2 - point.x - self.x) % p
        y = (slope * (self.x - x) - self.y) % p
        return Point(x, y, self.curve_config)

    def multiply(self, times):
        current_point = self
        current_coefficient = 1
        previous_points = []
        while current_coefficient < times:
            previous_points.append((current_coefficient, current_point))
            if 2 * current_coefficient <= times:
                current_point = current_point.add(current_point)
                current_coefficient = 2 * current_coefficient
            else:
                next_coefficient = 1
                next_point = self
                for (prev_coefficient, prev_point) in previous_points:
                    if prev_coefficient + current_coefficient <= times:
                        if prev_point.x != current_point.x:
                            if prev_coefficient > next_coefficient:
                                next_coefficient = prev_coefficient
                                next_point = prev_point
                current_point = current_point.add(next_point)
                current_coefficient = current_coefficient + next_coefficient
        return current_point

secp256k1_curve_config = {
    'a': 0,
    'b': 7,
    'p': 115792089237316195423570985008687907853269984665640564039457584007908834671663
}
p = secp256k1_curve_config['p']
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
g_x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
g_y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
g_point = Point(g_x, g_y, secp256k1_curve_config)

def bitcoin_message_hash(message):
    message = message.encode('utf-8')
    length = len(message)
    if length < 0xfd:
        length_bytes = length.to_bytes(1, 'big')
    elif length <= 0xffff:
        length_bytes = b'\xfd' + length.to_bytes(2, 'little')
    elif length <= 0xffffffff:
        length_bytes = b'\xfe' + length.to_bytes(4, 'little')
    else:
        length_bytes = b'\xff' + length.to_bytes(8, 'little')
    prefixed_message = b"\x18Bitcoin Signed Message:\n" + length_bytes + message
    return hashlib.sha256(hashlib.sha256(prefixed_message).digest()).digest()

def mod_sqrt(val, mod):
    return pow(val, (mod + 1) // 4, mod)

# Base58 encode (unchanged)
def base58_encode_bytes(data):
    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    val = int.from_bytes(data, 'big')
    encode = ''
    while val > 0:
        val, mod = divmod(val, 58)
        encode = chars[mod] + encode
    return '1' * leading_zeros + encode

# New: Base58 decode for WIF
def base58_decode(s):
    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    val = 0
    for char in s:
        idx = chars.find(char)
        if idx == -1:
            raise ValueError("Invalid Base58 character")
        val = val * 58 + idx
    byte_len = (val.bit_length() + 7) // 8
    bytes_val = val.to_bytes(byte_len, 'big')
    leading_ones = len(s) - len(s.lstrip('1'))
    return b'\x00' * leading_ones + bytes_val

# New: Decode WIF to private key int and compressed flag
def decode_wif(wif):
    decoded = base58_decode(wif)
    if len(decoded) not in (37, 38):
        raise ValueError("Invalid WIF length")
    prefix = decoded[0]
    if prefix != 0x80:
        raise ValueError("Invalid prefix (expected mainnet private key)")
    checksum = decoded[-4:]
    payload = decoded[:-4]
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if check != checksum:
        raise ValueError("Invalid WIF checksum")
    compressed = len(payload) == 34
    if compressed:
        if payload[-1] != 0x01:
            raise ValueError("Invalid compressed flag")
        priv_bytes = payload[1:-1]
    else:
        priv_bytes = payload[1:]
    private_key = int.from_bytes(priv_bytes, 'big')
    return private_key, compressed

def get_address_from_pubkey(point, compressed=True):
    if compressed:
        prefix = 2 if point.y % 2 == 0 else 3
        pub_bytes = prefix.to_bytes(1, 'big') + point.x.to_bytes(32, 'big')
    else:
        pub_bytes = b'\x04' + point.x.to_bytes(32, 'big') + point.y.to_bytes(32, 'big')
    sha = hashlib.sha256(pub_bytes).digest()
    h160 = hashlib.new('ripemd160', sha).digest()
    raw_address = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(raw_address).digest()).digest()[:4]
    address_bin = raw_address + checksum
    return base58_encode_bytes(address_bin)

def sign_bitcoin_message(message, private_key, compressed=True):
    z = int.from_bytes(bitcoin_message_hash(message), 'big')
    while True:
        k = random.randint(1, n-1)
        r_point = g_point.multiply(k)
        r = r_point.x % n
        if r == 0:
            continue
        k_inv = find_inverse(k, n)
        s = k_inv * (z + r * private_key) % n
        if s == 0:
            continue
        rec_id = (0 if r_point.y % 2 == 0 else 1) + (2 if r_point.x >= n else 0)
        if s > n // 2:
            s = n - s
            rec_id ^= 1
        header = 27 + rec_id + (4 if compressed else 0)
        sig_bin = header.to_bytes(1, 'big') + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        signature_b64 = base64.b64encode(sig_bin).decode('utf-8')
        public_key_point = g_point.multiply(private_key)
        address = get_address_from_pubkey(public_key_point, compressed)
        if verify_bitcoin_signature(message, signature_b64, address):
            return signature_b64, address

def verify_bitcoin_signature(message, signature_b64, address):
    try:
        sig = base64.b64decode(signature_b64)
        if len(sig) != 65:
            return False
        header = sig[0]
        r = int.from_bytes(sig[1:33], 'big')
        s = int.from_bytes(sig[33:], 'big')
        if header < 27 or header > 42 or s > n // 2:
            return False
        compressed = (header >= 31)
        rec_id = header - 27
        if compressed:
            rec_id -= 4
        z = int.from_bytes(bitcoin_message_hash(message), 'big')
        x = r + (rec_id // 2) * n
        if x >= p:
            return False
        y_sq = (pow(x, 3, p) + secp256k1_curve_config['a'] * x + secp256k1_curve_config['b']) % p
        y = mod_sqrt(y_sq, p)
        if pow(y, 2, p) != y_sq:
            return False
        if y % 2 != rec_id % 2:
            y = p - y
        R = Point(x, y, secp256k1_curve_config)
        r_inv = find_inverse(r, n)
        sr = s * r_inv % n
        zr = z * r_inv % n
        minus_zG = g_point.multiply((n - zr) % n)
        sR = R.multiply(sr)
        Q = sR.add(minus_zG)
        recovered_address = get_address_from_pubkey(Q, compressed)
        return recovered_address == address
    except Exception:
        return False

# Flask Routes (updated for WIF handling)
@app.route('/', methods=['GET'])
def home():
    return render_template_string('''
        <h1>Bitcoin Message Signer & Verifier</h1>
        <p><a href="/sign">Sign a Message</a></p>
        <p><a href="/verify">Verify a Signature</a></p>
    ''')

@app.route('/sign', methods=['GET', 'POST'])
def sign():
    if request.method == 'POST':
        message = request.form['message']
        privkey_input = request.form['privkey']
        try:
            # Try as hex first
            private_key = int(privkey_input, 16)
            compressed = True  # Default for hex input
        except ValueError:
            # Assume WIF
            private_key, compressed = decode_wif(privkey_input)
        try:
            signature, address = sign_bitcoin_message(message, private_key, compressed)
            return render_template_string('''
                <h1>Sign Result</h1>
                <p><strong>Signature (Base64):</strong> {{ signature }}</p>
                <p><strong>Derived Address:</strong> {{ address }}</p>
                <a href="/sign">Sign Another</a> | <a href="/">Home</a>
            ''', signature=signature, address=address)
        except Exception as e:
            return render_template_string('<h1>Error</h1><p>{{ error }}</p><a href="/sign">Try Again</a>', error=str(e))
    return render_template_string('''
        <h1>Sign a Message</h1>
        <form method="post">
            <label>Message:</label><br><textarea name="message" required></textarea><br>
            <label>Private Key (hex or WIF):</label><br><input type="text" name="privkey" required><br>
            <input type="submit" value="Sign">
        </form>
        <a href="/">Home</a>
    ''')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        message = request.form['message']
        signature = request.form['signature']
        address = request.form['address']
        verified = verify_bitcoin_signature(message, signature, address)
        result = 'Valid' if verified else 'Invalid'
        return render_template_string('''
            <h1>Verify Result</h1>
            <p><strong>Signature is:</strong> {{ result }}</p>
            <a href="/verify">Verify Another</a> | <a href="/">Home</a>
        ''', result=result)
    return render_template_string('''
        <h1>Verify a Signature</h1>
        <form method="post">
            <label>Message:</label><br><textarea name="message" required></textarea><br>
            <label>Signature (Base64):</label><br><input type="text" name="signature" required><br>
            <label>Address:</label><br><input type="text" name="address" required><br>
            <input type="submit" value="Verify">
        </form>
        <a href="/">Home</a>
    ''')

if __name__ == '__main__':
    app.run(debug=True)